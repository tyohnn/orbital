//! git 이 레이어에 바로 붙는 길(smart HTTP)과 코드를 올릴 때의 판정.
//!
//! 에이전트는 평범한 `git clone` · `git push` 로 코드를 주고받는다. 레이어가 받는 길은 셋뿐이다(`info/refs`, `git-upload-pack`, `git-receive-pack`).
//! 올리는 길은 두 갈래(git 의 `git-receive-pack`, 묶음)지만 무엇을 받는지는 여기의 [`judge_push`] 하나가 정한다.
//! 여기서는 글자만 다룬다. git 프로세스와 객체는 `orbital-source` 가 다룬다.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::scope::Action;

/// 레이어가 받는 유일한 ref. 열린 rollout 의 업데이트(`update`)는 받기만 한다.
pub const MAIN: &str = "refs/heads/main";

/// 없는 객체를 뜻하는 식별자. 새로 만드는 ref 의 앞과 지우는 ref 의 뒤에 온다.
pub const ZERO: &str = "0000000000000000000000000000000000000000";

/// git 의 두 서비스.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Service {
    /// 받기(`git clone` · `git fetch`).
    UploadPack,
    /// 올리기(`git push`).
    ReceivePack,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }

    /// 이 서비스에 필요한 토큰의 일. 받기는 코드를 읽는 일, 올리기는 쓰는 일이다.
    pub fn action(self) -> Action {
        match self {
            Self::UploadPack => Action::SourceRead,
            Self::ReceivePack => Action::SourceWrite,
        }
    }
}

/// git 의 길 하나.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", content = "service", rename_all = "snake_case")]
pub enum Route {
    /// `GET …/git/info/refs?service=…`: 어떤 ref 가 있는지 알린다.
    Advertise(Service),
    /// `POST …/git/git-upload-pack` · `POST …/git/git-receive-pack`: 객체를 주고받는다.
    Exchange(Service),
}

impl Route {
    pub fn service(self) -> Service {
        match self {
            Self::Advertise(service) | Self::Exchange(service) => service,
        }
    }

    /// 답의 `Content-Type`. git 은 이것을 보고 smart HTTP 인지 가른다.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Advertise(Service::UploadPack) => "application/x-git-upload-pack-advertisement",
            Self::Advertise(Service::ReceivePack) => "application/x-git-receive-pack-advertisement",
            Self::Exchange(Service::UploadPack) => "application/x-git-upload-pack-result",
            Self::Exchange(Service::ReceivePack) => "application/x-git-receive-pack-result",
        }
    }
}

impl Route {
    /// 이 길이 받는 요청의 `Content-Type`. 객체를 주고받는 `POST` 에만 있고 광고(`GET`)에는 없다.
    pub fn request_type(self) -> Option<&'static str> {
        match self {
            Self::Advertise(_) => None,
            Self::Exchange(Service::UploadPack) => Some("application/x-git-upload-pack-request"),
            Self::Exchange(Service::ReceivePack) => Some("application/x-git-receive-pack-request"),
        }
    }

    /// 요청의 `Content-Type` 을 받는가. 객체를 주고받는 길은 그 길의 git 의 것만 받는다(대소문자와 `;` 뒤의 매개변수는 보지 않는다).
    /// 브라우저의 폼이 보낼 수 있는 모양(`text/plain` · `application/x-www-form-urlencoded` · `multipart/form-data`)으로는 닿지 못한다.
    pub fn accepts(self, content_type: Option<&str>) -> bool {
        let Some(expected) = self.request_type() else {
            return true;
        };
        content_type
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
    }
}

/// `…/git/` 뒤의 경로와 질의에서 길을 고른다. 정해진 셋이 아니면 `None` 이다.
pub fn route(method: &str, tail: &[&str], query: &str) -> Option<Route> {
    match (method, tail) {
        ("GET", ["info", "refs"]) => {
            // 질의는 `service=…` 하나뿐이다
            let service = query.strip_prefix("service=")?;
            Service::parse(service).map(Route::Advertise)
        }
        ("POST", [name]) => Service::parse(name).map(Route::Exchange),
        _ => None,
    }
}

/// 40자의 소문자 16진수인가.
pub fn is_oid(text: &str) -> bool {
    text.len() == 40
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// ref 하나를 옮겨 달라는 요청. `old` 는 올리는 쪽이 아는 지금의 끝, `new` 는 옮길 곳이다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefUpdate {
    pub name: String,
    pub old: String,
    pub new: String,
}

/// 올린 것을 받지 않은 까닭. 문장은 에이전트가 읽고 무엇을 고칠지 안다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Refusal {
    /// 옮겨 달라는 ref 가 없다.
    Nothing,
    /// `main` 이 아닌 ref 다.
    OtherRef { name: String },
    /// ref 를 지우려 했다.
    Delete { name: String },
    /// 올리는 쪽이 아는 `main` 의 끝이 레이어의 것과 다르다. 그사이 다른 올리기가 있었다.
    Stale,
    /// 올린 commit 이 `main` 의 이력을 잇지 않는다.
    NotFastForward,
    /// 읽을 수 없는 요청이다.
    Malformed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nothing => f.write_str("올린 ref 가 없습니다. `main` 브랜치에 commit 한 뒤 올려 주세요"),
            Self::OtherRef { name } => write!(
                f,
                "`{name}` 은 받지 않습니다. 레이어는 `main` 브랜치 하나만 받습니다. 고친 것을 `main` 에 합쳐 올려 주세요"
            ),
            Self::Delete { name } => write!(f, "`{name}` 을 지우지 못합니다"),
            Self::Stale => f.write_str(
                "그사이 다른 올리기가 `main` 을 옮겼습니다. 레이어의 최신 commit 을 받아 합친 뒤 다시 올려 주세요",
            ),
            Self::NotFastForward => f.write_str(
                "올린 commit 이 레이어의 최신 commit 을 잇지 않습니다. 최신 commit 을 받아 합친 뒤 다시 올려 주세요(되돌리려면 되돌리는 commit 을 더해 올립니다)",
            ),
            Self::Malformed => f.write_str("올린 것을 읽지 못했습니다. 다시 올려 주세요"),
        }
    }
}

/// 올린 ref 들을 판정한다. `head` 는 레이어의 `main` 의 지금 끝이다. 받으면 `main` 을 옮길 commit 을 돌려준다.
///
/// 받는 것은 `main` 하나를 앞의 끝에서 옮기는 것뿐이다. 문제는 찾은 것을 모두 돌려준다.
pub fn judge_push(updates: &[RefUpdate], head: &str) -> Result<String, Vec<Refusal>> {
    if updates.is_empty() {
        return Err(vec![Refusal::Nothing]);
    }
    let readable = updates
        .iter()
        .all(|update| is_oid(&update.old) && is_oid(&update.new));
    let mains = updates.iter().filter(|update| update.name == MAIN).count();
    if !readable || mains > 1 {
        return Err(vec![Refusal::Malformed]);
    }
    let mut refusals = Vec::new();
    let mut target = None;
    for update in updates {
        if update.name != MAIN {
            refusals.push(Refusal::OtherRef {
                name: update.name.clone(),
            });
        } else if update.new == ZERO {
            refusals.push(Refusal::Delete {
                name: update.name.clone(),
            });
        } else if update.old != head {
            refusals.push(Refusal::Stale);
        } else {
            target = Some(update.new.clone());
        }
    }
    match target {
        Some(new) if refusals.is_empty() => Ok(new),
        _ => Err(refusals),
    }
}

// ---- 줄(pkt-line) ----

/// 끝을 알리는 줄(flush).
pub const FLUSH: &[u8] = b"0000";

/// 한 줄을 pkt-line 으로 싼다. 길이는 머리 넷을 함께 센다.
pub fn pkt(line: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", line.len() + 4).into_bytes();
    out.extend_from_slice(line);
    out
}

/// 줄 하나를 읽는다. `Some(None)` 은 끝을 알리는 줄이다. 읽지 못하면 `None` 이다.
fn read_pkt(bytes: &[u8]) -> Option<(Option<&[u8]>, &[u8])> {
    let head = std::str::from_utf8(bytes.get(..4)?).ok()?;
    let length = usize::from_str_radix(head, 16).ok()?;
    if length == 0 {
        return Some((None, &bytes[4..]));
    }
    if length < 4 {
        return None;
    }
    let line = bytes.get(4..length)?;
    Some((Some(line), &bytes[length..]))
}

/// `git-receive-pack` 의 첫 줄(`# service=…`)과 ref 의 광고. 받는 길은 `main` 하나만 알린다.
///
/// side-band 와 push-options 는 알리지 않는다. 그래서 올리는 쪽은 결과를 날것의 줄로 받고 선택지를 보내지 않는다.
pub fn advertise_receive(head: &str) -> Vec<u8> {
    let mut out = pkt(b"# service=git-receive-pack\n");
    out.extend_from_slice(FLUSH);
    out.extend(pkt(format!(
        "{head} {MAIN}\0report-status ofs-delta agent=orbital\n"
    )
    .as_bytes()));
    out.extend_from_slice(FLUSH);
    out
}

/// `git-upload-pack` 의 광고 앞에 붙는 첫 줄.
pub fn advertise_upload_prefix() -> Vec<u8> {
    let mut out = pkt(b"# service=git-upload-pack\n");
    out.extend_from_slice(FLUSH);
    out
}

/// `git-receive-pack` 의 요청: 옮겨 달라는 ref 들과, 그 뒤의 pack 이 시작하는 자리.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commands {
    pub updates: Vec<RefUpdate>,
    pub pack_at: usize,
}

/// `git-receive-pack` 의 요청 본문을 읽는다. shallow 와 push-cert 처럼 알리지 않은 것을 보냈으면 읽지 못한 것이다.
pub fn read_commands(body: &[u8]) -> Result<Commands, Refusal> {
    let mut rest = body;
    let mut updates = Vec::new();
    loop {
        let (line, after) = read_pkt(rest).ok_or(Refusal::Malformed)?;
        rest = after;
        let Some(line) = line else {
            break;
        };
        // 첫 줄은 NUL 뒤에 고른 선택지를 싣는다
        let line = line.split(|byte| *byte == 0).next().unwrap_or_default();
        let line = std::str::from_utf8(line).map_err(|_| Refusal::Malformed)?;
        let mut words = line.trim_end_matches('\n').splitn(3, ' ');
        let (Some(old), Some(new), Some(name)) = (words.next(), words.next(), words.next()) else {
            return Err(Refusal::Malformed);
        };
        if !is_oid(old) || !is_oid(new) {
            return Err(Refusal::Malformed);
        }
        updates.push(RefUpdate {
            name: name.to_owned(),
            old: old.to_owned(),
            new: new.to_owned(),
        });
    }
    Ok(Commands {
        updates,
        pack_at: body.len() - rest.len(),
    })
}

/// git bundle 의 머리: 먼저 있어야 하는 commit, 담긴 ref, pack 이 시작하는 자리.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub prerequisites: Vec<String>,
    /// (commit, ref 의 이름).
    pub refs: Vec<(String, String)>,
    pub pack_at: usize,
}

/// git bundle(v2 · v3)의 머리를 읽는다.
pub fn read_bundle(bytes: &[u8]) -> Result<Bundle, Refusal> {
    let mut rest = bytes;
    let next_line = |rest: &mut &[u8]| -> Result<String, Refusal> {
        let end = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(Refusal::Malformed)?;
        let line = std::str::from_utf8(&rest[..end]).map_err(|_| Refusal::Malformed)?;
        let line = line.to_owned();
        *rest = &rest[end + 1..];
        Ok(line)
    };
    let signature = next_line(&mut rest)?;
    if signature != "# v2 git bundle" && signature != "# v3 git bundle" {
        return Err(Refusal::Malformed);
    }
    let mut bundle = Bundle {
        prerequisites: Vec::new(),
        refs: Vec::new(),
        pack_at: 0,
    };
    loop {
        let line = next_line(&mut rest)?;
        if line.is_empty() {
            break;
        }
        if line.starts_with('@') {
            // v3 의 선택지. sha1 이 아닌 객체 형식은 받지 않는다
            if line.starts_with("@object-format=") && line != "@object-format=sha1" {
                return Err(Refusal::Malformed);
            }
            continue;
        }
        if let Some(prerequisite) = line.strip_prefix('-') {
            let oid = prerequisite.split(' ').next().unwrap_or_default();
            if !is_oid(oid) {
                return Err(Refusal::Malformed);
            }
            bundle.prerequisites.push(oid.to_owned());
            continue;
        }
        let (oid, name) = line.split_once(' ').ok_or(Refusal::Malformed)?;
        if !is_oid(oid) || name.is_empty() {
            return Err(Refusal::Malformed);
        }
        bundle.refs.push((oid.to_owned(), name.to_owned()));
    }
    bundle.pack_at = bytes.len() - rest.len();
    Ok(bundle)
}

/// 묶음에 담긴 ref 를 올리는 요청으로 옮긴다. 묶음은 앞의 끝을 적지 않으므로 레이어의 `main` 의 끝(`head`)에서 옮긴다고 본다.
/// `HEAD` 는 ref 가 아니라 받은 쪽이 꺼낼 브랜치의 표시라 뺀다.
pub fn bundle_updates(bundle: &Bundle, head: &str) -> Vec<RefUpdate> {
    bundle
        .refs
        .iter()
        .filter(|(_, name)| name != "HEAD")
        .map(|(oid, name)| RefUpdate {
            name: name.clone(),
            old: head.to_owned(),
            new: oid.clone(),
        })
        .collect()
}

/// `git-receive-pack` 의 결과(report-status). `unpacked` 가 `Err` 이면 객체를 받지 못한 것이고, 그때 모든 ref 는 받지 않은 것이다.
pub fn report(unpacked: Result<(), &str>, results: &[(String, Result<(), String>)]) -> Vec<u8> {
    let mut out = match unpacked {
        Ok(()) => pkt(b"unpack ok\n"),
        Err(why) => pkt(format!("unpack {}\n", one_line(why)).as_bytes()),
    };
    for (name, result) in results {
        let line = match result {
            Ok(()) => format!("ok {name}\n"),
            Err(why) => format!("ng {name} {}\n", one_line(why)),
        };
        out.extend(pkt(line.as_bytes()));
    }
    out.extend_from_slice(FLUSH);
    out
}

fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(c: char) -> String {
        std::iter::repeat_n(c, 40).collect()
    }

    fn update(name: &str, old: &str, new: &str) -> RefUpdate {
        RefUpdate {
            name: name.to_owned(),
            old: old.to_owned(),
            new: new.to_owned(),
        }
    }

    #[test]
    fn 객체를_주고받는_요청은_그_길의_git_의_content_type_만_받는다() {
        let upload = Route::Exchange(Service::UploadPack);
        let receive = Route::Exchange(Service::ReceivePack);
        assert!(upload.accepts(Some("application/x-git-upload-pack-request")));
        assert!(upload.accepts(Some(
            "Application/X-Git-Upload-Pack-Request; charset=binary"
        )));
        assert!(receive.accepts(Some("application/x-git-receive-pack-request")));
        for wrong in [
            None,
            Some(""),
            Some("application/x-git-receive-pack-request"),
            Some("application/x-git-upload-pack-requestx"),
            Some("application/json"),
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
            Some("multipart/form-data; boundary=x"),
        ] {
            assert!(!upload.accepts(wrong), "{wrong:?}");
        }
        assert!(!receive.accepts(Some("application/x-git-upload-pack-request")));
        // 광고(`GET`)는 본문이 없어 무엇이든 받는다
        assert!(Route::Advertise(Service::UploadPack).accepts(None));
    }

    #[test]
    fn git_의_길은_정해진_셋만_받는다() {
        let up = "service=git-upload-pack";
        let receive = "service=git-receive-pack";
        assert_eq!(
            route("GET", &["info", "refs"], up),
            Some(Route::Advertise(Service::UploadPack))
        );
        assert_eq!(
            route("GET", &["info", "refs"], receive),
            Some(Route::Advertise(Service::ReceivePack))
        );
        assert_eq!(
            route("POST", &["git-upload-pack"], ""),
            Some(Route::Exchange(Service::UploadPack))
        );
        assert_eq!(
            route("POST", &["git-receive-pack"], ""),
            Some(Route::Exchange(Service::ReceivePack))
        );
        for (method, tail, query) in [
            // 서비스가 없거나 모르는 것이다
            ("GET", &["info", "refs"][..], ""),
            ("GET", &["info", "refs"][..], "service=git-upload-archive"),
            (
                "GET",
                &["info", "refs"][..],
                "service=git-upload-pack&service=x",
            ),
            // 방법이 다르다
            ("POST", &["info", "refs"][..], up),
            ("GET", &["git-upload-pack"][..], ""),
            ("PUT", &["git-receive-pack"][..], ""),
            // dumb HTTP 와 저장소의 파일은 내주지 않는다
            ("GET", &["HEAD"][..], ""),
            ("GET", &["objects", "info", "packs"][..], ""),
            ("GET", &["config"][..], ""),
            ("GET", &["hooks", "pre-receive"][..], ""),
            ("POST", &["git-upload-archive"][..], ""),
            // 길이 더 붙었다
            ("POST", &["git-receive-pack", "x"][..], ""),
            ("GET", &["info", "refs", "x"][..], up),
            ("GET", &[][..], up),
        ] {
            assert_eq!(
                route(method, tail, query),
                None,
                "{method} {tail:?} {query}"
            );
        }
        // 서비스에 따라 토큰의 일이 갈린다
        assert_eq!(Service::UploadPack.action(), Action::SourceRead);
        assert_eq!(Service::ReceivePack.action(), Action::SourceWrite);
    }

    #[test]
    fn 올리는_ref_는_main_하나만_받는다() {
        let head = oid('a');
        let next = oid('b');
        // main 하나를 지금의 끝에서 옮긴다
        assert_eq!(
            judge_push(&[update(MAIN, &head, &next)], &head),
            Ok(next.clone())
        );
        // 다른 브랜치 · 태그 · 레이어가 안에서 쓰는 ref
        for name in [
            "refs/heads/update",
            "refs/heads/feature",
            "refs/tags/v1",
            "refs/orbital/base",
            "HEAD",
        ] {
            assert_eq!(
                judge_push(&[update(name, ZERO, &next)], &head),
                Err(vec![Refusal::OtherRef {
                    name: name.to_owned()
                }]),
                "{name}"
            );
        }
        // main 과 함께 다른 것을 올려도 하나도 받지 않는다
        assert_eq!(
            judge_push(
                &[
                    update(MAIN, &head, &next),
                    update("refs/heads/feature", ZERO, &next)
                ],
                &head
            ),
            Err(vec![Refusal::OtherRef {
                name: "refs/heads/feature".to_owned()
            }])
        );
        // 지우기
        assert_eq!(
            judge_push(&[update(MAIN, &head, ZERO)], &head),
            Err(vec![Refusal::Delete {
                name: MAIN.to_owned()
            }])
        );
        // 아무것도 옮기지 않는다
        assert_eq!(judge_push(&[], &head), Err(vec![Refusal::Nothing]));
        // 올리는 쪽이 아는 끝이 낡았다
        assert_eq!(
            judge_push(&[update(MAIN, &oid('c'), &next)], &head),
            Err(vec![Refusal::Stale])
        );
        // 같은 main 을 두 번 적었다
        assert_eq!(
            judge_push(
                &[update(MAIN, &head, &next), update(MAIN, &head, &oid('d'))],
                &head
            ),
            Err(vec![Refusal::Malformed])
        );
        // 식별자가 아닌 글자
        assert_eq!(
            judge_push(&[update(MAIN, &head, "--upload-pack=x")], &head),
            Err(vec![Refusal::Malformed])
        );
        // 문제는 모두 돌려준다
        assert_eq!(
            judge_push(
                &[
                    update("refs/tags/v1", ZERO, &next),
                    update("refs/heads/x", &head, ZERO)
                ],
                &head
            ),
            Err(vec![
                Refusal::OtherRef {
                    name: "refs/tags/v1".to_owned()
                },
                Refusal::OtherRef {
                    name: "refs/heads/x".to_owned()
                },
            ])
        );
    }

    #[test]
    fn 받지_않은_까닭은_한_줄의_문장이고_무엇을_고칠지_말한다() {
        for refusal in [
            Refusal::Nothing,
            Refusal::OtherRef {
                name: "refs/heads/x".to_owned(),
            },
            Refusal::Delete {
                name: MAIN.to_owned(),
            },
            Refusal::Stale,
            Refusal::NotFastForward,
            Refusal::Malformed,
        ] {
            let text = refusal.to_string();
            assert!(!text.is_empty() && !text.contains('\n'), "{refusal:?}");
            // host 를 모른다. 어느 도구 · 명령으로 하는지는 팩토리의 스킬이 말한다
            assert!(!text.contains("orbital"), "{text}");
            assert!(!text.contains("/v1/"), "{text}");
        }
        assert!(Refusal::NotFastForward.to_string().contains("받아 합친 뒤"));
        assert!(
            Refusal::OtherRef {
                name: "refs/heads/x".to_owned()
            }
            .to_string()
            .contains("`main`")
        );
    }

    #[test]
    fn 올리기의_요청은_ref_의_줄과_그_뒤의_pack_으로_읽는다() {
        let (head, next) = (oid('a'), oid('b'));
        let mut body = pkt(format!("{head} {next} {MAIN}\0report-status agent=git/2\n").as_bytes());
        body.extend(pkt(format!("{ZERO} {next} refs/tags/v1\n").as_bytes()));
        body.extend_from_slice(FLUSH);
        let at = body.len();
        body.extend_from_slice(b"PACK....");
        let commands = read_commands(&body).unwrap();
        assert_eq!(commands.pack_at, at);
        assert_eq!(
            commands.updates,
            vec![
                update(MAIN, &head, &next),
                update("refs/tags/v1", ZERO, &next)
            ]
        );
        // 끝나지 않은 줄 · 길이가 틀린 줄 · shallow 처럼 알리지 않은 줄
        assert_eq!(read_commands(b"00"), Err(Refusal::Malformed));
        assert_eq!(read_commands(b"0003"), Err(Refusal::Malformed));
        assert_eq!(read_commands(b"ffff abc"), Err(Refusal::Malformed));
        let mut shallow = pkt(format!("shallow {head}\n").as_bytes());
        shallow.extend_from_slice(FLUSH);
        assert_eq!(read_commands(&shallow), Err(Refusal::Malformed));
    }

    #[test]
    fn 묶음의_머리에서_ref_를_읽고_head_는_올리는_ref_로_치지_않는다() {
        let (head, next) = (oid('a'), oid('b'));
        let text =
            format!("# v2 git bundle\n-{head} 앞의 commit\n{next} HEAD\n{next} {MAIN}\n\nPACK");
        let bundle = read_bundle(text.as_bytes()).unwrap();
        assert_eq!(bundle.prerequisites, vec![head.clone()]);
        assert_eq!(&text.as_bytes()[bundle.pack_at..], b"PACK");
        assert_eq!(
            bundle_updates(&bundle, &head),
            vec![update(MAIN, &head, &next)]
        );
        assert!(read_bundle(b"this is not a bundle").is_err());
        assert!(read_bundle(b"# v2 git bundle\nnot-an-oid refs/heads/main\n\n").is_err());
        assert!(read_bundle(b"# v3 git bundle\n@object-format=sha256\n\n").is_err());
    }

    #[test]
    fn 결과는_ref_마다_한_줄이고_까닭은_한_줄로_접는다() {
        let text = report(
            Ok(()),
            &[(MAIN.to_owned(), Err("첫 줄\n둘째 줄".to_owned()))],
        );
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "000eunpack ok\n002ang refs/heads/main 첫 줄 둘째 줄\n0000"
        );
        let advertised = String::from_utf8(advertise_receive(&oid('a'))).unwrap();
        assert!(advertised.starts_with("001f# service=git-receive-pack\n0000"));
        assert!(advertised.contains("refs/heads/main\0report-status"));
        assert!(!advertised.contains("side-band") && !advertised.contains("push-options"));
    }
}
