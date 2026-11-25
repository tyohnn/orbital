//! 이 기계에 세운 PostgreSQL 클러스터 하나. 시점 복구로 옆에 세운 것과, 테스트가 운영 클러스터로 쓰려고 세운 것.
//!
//! 내리면(drop) 프로세스를 멈추고 세울 때 받은 폴더를 통째로 지운다.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orbital_core::backup::RecoveryFailure;
use postgres::{Client, Config, NoTls};

use crate::{Error, Tools, pg};

/// 옆의 클러스터가 듣는 포트 번호. TCP 는 듣지 않으니 소켓 파일의 이름에만 쓰인다.
const SOCKET_PORT: u16 = 5432;

#[derive(Debug)]
pub struct Cluster {
    tools: Tools,
    /// 세울 때 받은 폴더. 내리면 통째로 지운다.
    root: PathBuf,
    data: PathBuf,
    socket: PathBuf,
    /// TCP 로 듣는 포트. 옆에 세운 클러스터는 듣지 않는다.
    tcp: Option<u16>,
    /// 관리 역할(클러스터를 세운 사용자).
    user: String,
}

/// 비어 있는 TCP 포트 하나.
fn free_port() -> Result<u16, Error> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|_| Error::Io {
            doing: "빈 포트를 찾",
        })
}

impl Cluster {
    /// **시험용.** 새 클러스터를 세운다. `127.0.0.1` 의 빈 포트와 소켓에서 듣고, `archive` 를 주면 WAL 을 그 폴더에 보관한다.
    ///
    /// WAL 조각은 1MB 로 작게 두어 테스트가 디스크를 적게 쓴다. `root` 는 Postgres 의 사용자가 닿는 자리여야 한다.
    pub fn init(tools: &Tools, root: &Path, archive: Option<&str>) -> Result<Self, Error> {
        tools.private_folder(root)?;
        let data = root.join("data");
        let socket = root.join("sock");
        tools.private_folder(&socket)?;
        let mut command = tools.tool("initdb");
        command.arg("-D").arg(&data).args([
            "-U",
            "postgres",
            "-A",
            "trust",
            "--wal-segsize=1",
            "--no-sync",
            "--locale=C",
            "-E",
            "UTF8",
        ]);
        Tools::run(command, "클러스터를 세우")?;
        let port = free_port()?;
        let mut settings = format!(
            "port = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{}'\n\
             max_connections = 60\nshared_buffers = '16MB'\nfsync = off\nwal_level = replica\nmax_wal_senders = 4\n",
            socket.display()
        );
        if let Some(command) = archive {
            settings.push_str(&format!(
                "archive_mode = on\narchive_command = '{}'\n",
                command.replace('\'', "''")
            ));
        }
        tools.write(&data.join("postgresql.auto.conf"), &settings, true)?;
        let cluster = Self {
            tools: tools.clone(),
            root: root.to_owned(),
            data,
            socket,
            tcp: Some(port),
            user: "postgres".to_owned(),
        };
        cluster.start()?;
        cluster.ready(Duration::from_secs(30))?;
        Ok(cluster)
    }

    /// 기반 백업의 사본(`data`)을 시점 복구로 띄운다. 유닉스 소켓(`root/sock`, Postgres 의 사용자만 들어가는 폴더)에서만 듣는다.
    pub(crate) fn recover(
        tools: &Tools,
        root: &Path,
        restore_command: &str,
        target: &str,
        user: &str,
    ) -> Result<Self, Error> {
        let data = root.join("data");
        let socket = root.join("sock");
        tools.private_folder(&socket)?;
        let settings = format!(
            "\n# 레이어가 옆에 되살린 클러스터. TCP 를 듣지 않고 WAL 을 보관하지 않는다\n\
             restore_command = '{}'\nrecovery_target_time = '{target}'\nrecovery_target_action = 'promote'\n\
             archive_mode = off\nhot_standby = off\nlisten_addresses = ''\nunix_socket_directories = '{}'\n\
             port = {SOCKET_PORT}\nmax_connections = 20\nshared_buffers = '16MB'\nfsync = off\n",
            restore_command.replace('\'', "''"),
            socket.display()
        );
        tools.write(&data.join("postgresql.auto.conf"), &settings, true)?;
        // 소켓 폴더에 닿는 것은 Postgres 의 사용자(와 root)뿐이다. 그 안에서만 믿는다
        tools.write(&data.join("pg_hba.conf"), "local all all trust\n", false)?;
        tools.write(&data.join("recovery.signal"), "", false)?;
        let cluster = Self {
            tools: tools.clone(),
            root: root.to_owned(),
            data,
            socket,
            tcp: None,
            user: user.to_owned(),
        };
        if cluster.start().is_err() {
            return Err(Error::Recovery(cluster.failure()));
        }
        cluster.ready(Duration::from_secs(300))?;
        Ok(cluster)
    }

    fn start(&self) -> Result<(), Error> {
        let mut command = self.tools.tool("pg_ctl");
        command
            .arg("-D")
            .arg(&self.data)
            .arg("-l")
            .arg(self.root.join("log"))
            .args(["-w", "-t", "300", "start"]);
        Tools::run(command, "클러스터를 띄우")
    }

    /// 접속을 받고 복구가 끝날 때까지 기다린다. `pg_ctl -w` 는 복구가 실패해 프로세스가 내려가도 「떴다」고 답할 수 있어 직접 본다.
    fn ready(&self, limit: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + limit;
        loop {
            if let Ok(mut client) = self.connect("postgres") {
                let recovering: bool = client
                    .query_one("SELECT pg_is_in_recovery()", &[])
                    .map_err(pg("복구가 끝났는지 보"))?
                    .get(0);
                if !recovering {
                    return Ok(());
                }
            }
            if !self.running() || Instant::now() >= deadline {
                return Err(Error::Recovery(self.failure()));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn running(&self) -> bool {
        let mut command = self.tools.tool("pg_ctl");
        command.arg("-D").arg(&self.data).arg("status");
        Tools::run(command, "클러스터가 떠 있는지 보").is_ok()
    }

    /// Postgres 의 기록에서 갈래만 읽는다. 기록의 글은 밖으로 내보내지 않는다.
    fn failure(&self) -> RecoveryFailure {
        let mut command = self.tools.system("cat");
        command
            .arg(self.root.join("log"))
            .stdout(std::process::Stdio::piped());
        let log = command
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        if log.contains("recovery ended before configured recovery target was reached") {
            RecoveryFailure::TargetNotReached
        } else if log.contains("could not locate required checkpoint record")
            || log.contains("requested WAL segment")
        {
            RecoveryFailure::WalMissing
        } else {
            RecoveryFailure::DidNotStart
        }
    }

    /// 관리 역할로 database 하나에 붙는다. 유닉스 소켓으로 붙는다.
    pub fn connect(&self, database: &str) -> Result<Client, Error> {
        Config::new()
            .host_path(&self.socket)
            .port(self.port())
            .user(&self.user)
            .dbname(database)
            .connect(NoTls)
            .map_err(pg("클러스터에 붙"))
    }

    fn port(&self) -> u16 {
        self.tcp.unwrap_or(SOCKET_PORT)
    }

    /// TCP 로 붙는 관리 주소. 옆에 세운 클러스터에는 없다.
    pub fn url(&self) -> Option<String> {
        self.tcp
            .map(|port| format!("postgres://{}@127.0.0.1:{port}/postgres", self.user))
    }

    /// 이 클러스터가 TCP 로 듣는 주소. 듣지 않으면 비어 있다.
    pub fn listen_addresses(&self) -> Result<String, Error> {
        let mut client = self.connect("postgres")?;
        Ok(client
            .query_one("SHOW listen_addresses", &[])
            .map_err(pg("듣는 주소를 읽"))?
            .get(0))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn tools(&self) -> &Tools {
        &self.tools
    }

    pub(crate) fn user(&self) -> &str {
        &self.user
    }

    pub(crate) fn socket_port(&self) -> u16 {
        self.port()
    }

    /// 멈춘다. 붙어 있는 연결을 끊는다.
    pub fn stop(&self) {
        let mut command = self.tools.tool("pg_ctl");
        command
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "immediate", "-w", "stop"]);
        let _ = Tools::run(command, "클러스터를 멈추");
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop();
        let _ = self.tools.remove(&self.root);
    }
}
