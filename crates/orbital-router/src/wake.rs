//! 서버 서비스 하나를 재우고 깨운다.
//!
//! router 는 서버 서비스로 요청을 넘기기 전에 [`AppServer::enter`] 로 그 서비스가 떠 있는지 본다. 자고 있으면 띄우고(실행기의 `start`),
//! 포트가 열릴 때까지 기다렸다가 넘긴다. 동시에 온 첫 요청들은 한 번의 깨우기를 함께 기다린다(깨우는 문은 하나다).
//! 마지막 요청의 답이 끝까지 나간 뒤 정한 시간 동안 요청이 없으면 프로세스를 내린다. 처리 중인 요청이 있으면 재우지 않는다.
//! 깨우지 못하면 부르는 쪽이 503 과 `Retry-After` 로 답하고, 다음 요청이 다시 깨운다.
//! 깨우기를 기다리는 요청의 수에는 서비스마다 상한이 있다. 넘친 요청은 기다리지 않고 곧바로 503 으로 돌려보내,
//! 자는 서비스를 향한 요청의 홍수가 기다리는 연결과 메모리를 끝없이 쌓지 못하게 한다.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use orbital_run::Running;

use crate::{Body, Note};

/// 서비스를 깨우지 못한 갈래. 기록에는 서비스의 이름과 이 갈래만 적는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeFailure {
    /// 실행기가 시작하지 못했다.
    Refused,
    /// 떴지만 포트를 열기 전에 끝났다.
    Exited,
    /// 정한 시간 안에 포트가 열리지 않았다.
    TimedOut,
    /// 깨우는 차례를 기다리다 정한 시간을 넘겼다.
    Busy,
    /// 인스턴스를 내리는 중이다.
    Closed,
    /// 깨우기를 기다리는 요청이 상한에 찼다. 기다리지 않고 돌려보낸다.
    Overloaded,
}

impl std::fmt::Display for WakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Refused => "refused",
            Self::Exited => "exited",
            Self::TimedOut => "timed_out",
            Self::Busy => "busy",
            Self::Closed => "closed",
            Self::Overloaded => "overloaded",
        })
    }
}

/// 서비스의 프로세스를 띄우는 것. 레이어가 실행기로 짓는다. 동기로 돌고(`spawn_blocking` 에서 부른다),
/// 포트가 열릴 때까지 기다렸다가 돌려준다. 시간 안에 열리지 않으면 띄운 것을 내리고 실패를 돌려준다.
pub trait Starter: Send + Sync {
    fn start(&self, port: u16) -> Result<Box<dyn Running>, WakeFailure>;
}

/// 떠 있는 프로세스와 그리로 가는 연결 묶음. 잘 때 함께 버려서, 내린 프로세스의 연결을 다시 쓰지 않는다.
struct Awake {
    process: Box<dyn Running>,
    port: u16,
    client: Client<HttpConnector, Body>,
}

#[derive(Default)]
struct State {
    awake: Option<Awake>,
    /// 처리 중인 요청의 수. 답의 본문이 끝까지 나가야 줄어든다.
    in_flight: usize,
    /// 요청이 들어올 때마다 는다. 재우는 타이머는 자기가 선 뒤로 요청이 없었을 때만 재운다.
    generation: u64,
    closed: bool,
    /// 처리 중인 요청이 끝나면 곧바로 재운다. 앱에 건넬 값(비밀)이 바뀌었을 때 선다.
    refresh: bool,
    /// 깨우기를 기다리는 요청의 수(깨우는 문을 쥔 것까지).
    waiting: usize,
}

/// 서버 서비스 하나.
pub struct AppServer {
    name: String,
    starter: Arc<dyn Starter>,
    sleep_after: Duration,
    wake_timeout: Duration,
    /// 깨우기를 기다리는 요청의 상한.
    wait_limit: usize,
    state: Mutex<State>,
    /// 깨우는 문. 깨우기와 재우기는 이 문을 쥔 하나만 한다. 그래서 내리는 중인 프로세스의 포트에 새 프로세스가 겹치지 않는다.
    gate: tokio::sync::Mutex<()>,
    note: Mutex<Option<Note>>,
    /// 재우는 타이머를 거는 런타임. 레이어가 동기로 부르는 자리([`AppServer::adopt`])에서도 걸 수 있게 받아 둔다.
    runtime: tokio::runtime::Handle,
}

/// 요청 하나가 서비스에 들어가 있는 동안의 표. 떨어지면(답의 본문이 끝나면) 처리 중인 수가 준다.
pub(crate) struct Visit {
    server: Arc<AppServer>,
    pub(crate) port: u16,
    pub(crate) client: Client<HttpConnector, Body>,
}

impl Drop for Visit {
    fn drop(&mut self) {
        self.server.leave();
    }
}

/// 깨우기를 기다리는 자리 하나. 기다림이 끝나면(깨웠든, 못 깨웠든, 요청이 끊겼든) 떨어지며 자리를 돌려준다.
struct Waiting<'a> {
    server: &'a AppServer,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let mut state = self.server.lock();
        state.waiting = state.waiting.saturating_sub(1);
    }
}

/// 포트를 열기 전에 끝난 앱을 포트를 바꿔 띄워 보는 횟수(처음 것 포함).
const START_ATTEMPTS: usize = 2;

/// 빈 포트를 받아 서비스를 띄운다. 띄운 프로세스와 그 포트를 돌려준다.
///
/// 받은 포트는 잡았다 놓은 것이라, 앱이 듣기 전에 이 기계의 다른 프로세스가 먼저 잡을 수 있다(나가는 연결의 임시 포트도 같은
/// 범위에서 나온다). 그러면 앱은 듣지 못하고 끝난다. 포트를 바꿔 한 번 더 띄운다. 앱이 제 잘못으로 끝나는 것이면 다시 띄워도
/// 끝나므로 두 번에서 멈춘다.
pub fn start_on_free_port(starter: &dyn Starter) -> Result<(Box<dyn Running>, u16), WakeFailure> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let port = orbital_run::free_port().ok_or(WakeFailure::Refused)?;
        match starter.start(port) {
            Ok(process) => return Ok((process, port)),
            Err(WakeFailure::Exited) if attempts < START_ATTEMPTS => {}
            Err(failure) => return Err(failure),
        }
    }
}

impl AppServer {
    /// `wait_limit` 은 깨우기를 기다리는 요청의 상한이다(0 이면 1 로 본다).
    pub fn new(
        name: impl Into<String>,
        starter: Arc<dyn Starter>,
        sleep_after: Duration,
        wake_timeout: Duration,
        wait_limit: usize,
        runtime: tokio::runtime::Handle,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            starter,
            sleep_after,
            wake_timeout,
            wait_limit: wait_limit.max(1),
            state: Mutex::new(State::default()),
            gate: tokio::sync::Mutex::new(()),
            note: Mutex::new(None),
            runtime,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 지금 떠 있는 프로세스를 넣는다. 레이어가 프리뷰와 승격에서 새 서버가 실제로 뜨는지 확인한 뒤에 넘긴다.
    /// 요청이 오지 않으면 정한 시간 뒤에 잔다.
    pub fn adopt(self: &Arc<Self>, process: Box<dyn Running>, port: u16) {
        let generation = {
            let mut state = self.lock();
            if state.closed {
                drop(state);
                let mut process = process;
                process.stop();
                return;
            }
            state.awake = Some(Awake {
                process,
                port,
                client: new_client(),
            });
            state.generation += 1;
            state.generation
        };
        self.schedule_sleep(generation);
    }

    /// 서비스를 내린다. 다시 깨우지 않는다. 레이어가 인스턴스를 내리거나 바꿀 때 부른다(동기).
    pub fn close(&self) {
        let awake = {
            let mut state = self.lock();
            state.closed = true;
            state.awake.take()
        };
        if let Some(mut awake) = awake {
            awake.process.stop();
        }
    }

    /// 떠 있는 프로세스를 곧바로 재운다. 다음 요청은 새로 깨운 프로세스가 받는다. 앱에 건넬 값(비밀)이 바뀌었을 때 레이어가 부른다(동기).
    ///
    /// 처리 중인 요청이 있으면 그 요청이 끝난 뒤에 재운다. 깨우는 중이던 프로세스는 바뀌기 전의 값을 읽었을 수 있어, 그 첫 요청이 끝나면 재운다.
    pub fn refresh(&self) {
        let awake = {
            let mut state = self.lock();
            if state.in_flight > 0 {
                state.refresh = true;
                None
            } else if state.awake.is_some() {
                state.generation += 1;
                state.awake.take()
            } else {
                // 자고 있으면 할 것이 없다. 깨우는 문이 잠겨 있으면 지금 깨우는 중이다
                if self.gate.try_lock().is_err() {
                    state.refresh = true;
                }
                None
            }
        };
        if let Some(mut awake) = awake {
            awake.process.stop();
        }
    }

    /// 지금 프로세스가 떠 있는가.
    pub fn is_awake(&self) -> bool {
        self.lock().awake.is_some()
    }

    pub(crate) fn attach(&self, note: Note) {
        if let Ok(mut slot) = self.note.lock() {
            *slot = Some(note);
        }
    }

    fn record(&self, failure: WakeFailure) {
        let note = self.note.lock().ok().and_then(|note| note.clone());
        if let Some(note) = note {
            note.line(&format!("WAKE {} {failure}", self.name));
        }
    }

    /// 떠 있으면 들어간다. `alive` 를 보고 죽었으면 떠 있지 않은 것으로 본다.
    fn try_enter(self: &Arc<Self>) -> Result<Option<Visit>, WakeFailure> {
        let mut state = self.lock();
        if state.closed {
            return Err(WakeFailure::Closed);
        }
        let alive = state
            .awake
            .as_mut()
            .is_some_and(|awake| awake.process.alive());
        let Some(awake) = state.awake.as_ref().filter(|_| alive) else {
            return Ok(None);
        };
        let (port, client) = (awake.port, awake.client.clone());
        state.in_flight += 1;
        state.generation += 1;
        Ok(Some(Visit {
            server: Arc::clone(self),
            port,
            client,
        }))
    }

    /// 요청 하나가 들어간다. 자고 있으면 깨운다. 깨우지 못하면 갈래를 돌려준다.
    pub(crate) async fn enter(self: &Arc<Self>) -> Result<Visit, WakeFailure> {
        if let Some(visit) = self.try_enter()? {
            return Ok(visit);
        }
        // 기다리는 자리가 찼으면 기다리지 않는다
        let _waiting = {
            let mut state = self.lock();
            if state.waiting >= self.wait_limit {
                return Err(WakeFailure::Overloaded);
            }
            state.waiting += 1;
            Waiting { server: self }
        };
        // 깨우는 문을 기다리는 시간에도 상한을 둔다. 앞의 깨우기 하나가 끝나기를 기다리는 만큼이다
        let Ok(_gate) = tokio::time::timeout(self.wake_timeout * 2, self.gate.lock()).await else {
            self.record(WakeFailure::Busy);
            return Err(WakeFailure::Busy);
        };
        // 앞의 요청이 이미 깨웠을 수 있다
        if let Some(visit) = self.try_enter()? {
            return Ok(visit);
        }
        // 죽은 프로세스가 남았으면 거둔다
        let dead = self.lock().awake.take();
        if let Some(mut dead) = dead {
            let _ = tokio::task::spawn_blocking(move || dead.process.stop()).await;
        }
        let starter = Arc::clone(&self.starter);
        let started = tokio::task::spawn_blocking(move || start_on_free_port(starter.as_ref()))
            .await
            .unwrap_or(Err(WakeFailure::Refused));
        let (process, port) = match started {
            Ok(started) => started,
            Err(failure) => {
                self.record(failure);
                return Err(failure);
            }
        };
        let client = new_client();
        let refused = {
            let mut state = self.lock();
            if state.closed {
                Some(process)
            } else {
                state.awake = Some(Awake {
                    process,
                    port,
                    client: client.clone(),
                });
                state.in_flight += 1;
                state.generation += 1;
                None
            }
        };
        if let Some(mut process) = refused {
            let _ = tokio::task::spawn_blocking(move || process.stop()).await;
            return Err(WakeFailure::Closed);
        }
        Ok(Visit {
            server: Arc::clone(self),
            port,
            client,
        })
    }

    /// 요청 하나가 끝났다. 처리 중인 것이 없으면 재우는 타이머를 건다.
    fn leave(self: &Arc<Self>) {
        let generation = {
            let mut state = self.lock();
            state.in_flight = state.in_flight.saturating_sub(1);
            if state.in_flight > 0 {
                return;
            }
            if state.refresh {
                state.refresh = false;
                state.generation += 1;
                let awake = state.awake.take();
                drop(state);
                if let Some(mut awake) = awake {
                    self.runtime.spawn_blocking(move || awake.process.stop());
                }
                return;
            }
            state.generation
        };
        self.schedule_sleep(generation);
    }

    /// 정한 시간 뒤에, 그동안 요청이 없었으면 재운다.
    fn schedule_sleep(self: &Arc<Self>, generation: u64) {
        let server = Arc::clone(self);
        self.runtime.spawn(async move {
            tokio::time::sleep(server.sleep_after).await;
            let _gate = server.gate.lock().await;
            let awake = {
                let mut state = server.lock();
                if state.in_flight > 0 || state.generation != generation {
                    return;
                }
                state.awake.take()
            };
            if let Some(mut awake) = awake {
                let _ = tokio::task::spawn_blocking(move || awake.process.stop()).await;
            }
        });
    }
}

fn new_client() -> Client<HttpConnector, Body> {
    // 앱으로 가는 연결은 살려 두고 다시 쓴다. 잘 때 이 묶음을 버린다
    Client::builder(TokioExecutor::new()).build_http()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// 살아 있는 척하는 프로세스.
    struct Fake;

    impl Running for Fake {
        fn alive(&mut self) -> bool {
            true
        }

        fn stop(&mut self) {}
    }

    /// 처음 `exits` 번은 포트를 열기 전에 끝나고, 그 뒤로는 뜬다. 받은 포트를 적어 둔다.
    struct Flaky {
        exits: usize,
        calls: AtomicUsize,
        ports: Mutex<Vec<u16>>,
    }

    impl Starter for Flaky {
        fn start(&self, port: u16) -> Result<Box<dyn Running>, WakeFailure> {
            self.ports.lock().unwrap().push(port);
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.exits {
                return Err(WakeFailure::Exited);
            }
            Ok(Box::new(Fake))
        }
    }

    fn server(exits: usize) -> (tokio::runtime::Runtime, Arc<Flaky>, Arc<AppServer>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let starter = Arc::new(Flaky {
            exits,
            calls: AtomicUsize::new(0),
            ports: Mutex::new(Vec::new()),
        });
        let server = AppServer::new(
            "web",
            Arc::clone(&starter) as Arc<dyn Starter>,
            Duration::from_secs(3600),
            Duration::from_secs(5),
            8,
            runtime.handle().clone(),
        );
        (runtime, starter, server)
    }

    #[test]
    fn 포트를_열기_전에_끝나면_다른_포트로_한_번_더_띄운다() {
        // 받은 포트를 그사이 다른 프로세스가 잡으면 앱은 듣지 못하고 끝난다. 포트를 바꿔 한 번 더 띄운다
        let (runtime, starter, server) = server(1);
        let visit = runtime.block_on(server.enter());
        assert!(visit.is_ok(), "{:?}", visit.err());
        let ports = starter.ports.lock().unwrap().clone();
        assert_eq!(ports.len(), 2);
        assert_ne!(ports[0], ports[1]);
        drop(visit);
    }

    #[test]
    fn 다시_띄워도_끝나면_더_띄우지_않고_끝났다고_알린다() {
        // 앱이 제 잘못으로 끝나는 것이면 되풀이해도 소용없다. 두 번에서 멈춘다
        let (runtime, starter, server) = server(usize::MAX);
        let failure = runtime.block_on(server.enter()).err();
        assert_eq!(failure, Some(WakeFailure::Exited));
        assert_eq!(starter.calls.load(Ordering::SeqCst), 2);
    }
}
