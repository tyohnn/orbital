//! DB proxy.
//!
//! 서비스는 비밀번호 없이, 업무 역할의 이름만으로 proxy 에 붙는다. proxy 는 듣는 자리로 어느 인스턴스의 어느 서비스인지를 알고,
//! 그 서비스의 선언에 있는 역할이면 그 로그인으로 DB 에 대신 들어간다. 그 뒤로는 양쪽의 바이트를 그대로 나른다.
//!
//! 비밀번호는 어디에도 없다. 역할에 비밀번호를 주지 않고, DB 는 proxy 만 닿는 자리에서 온 연결만 받는다.
//! DB 가 비밀번호를 물으면 proxy 는 그 물음을 서비스에게 넘기지 않고 연결을 닫는다. 서비스가 비밀번호를 알 일이 없어야 하기 때문이다.
//!
//! 듣는 자리 하나가 서비스 하나다([`serve`]). 운영에서는 그 서비스의 서버만 닿는 주소에서 듣는다.

use std::io;

use orbital_core::manifest::ValidManifest;
use orbital_core::name::Ident;
use orbital_core::plan::{Names, logins};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod startup;

pub use startup::Route;
use startup::{First, MAX_STARTUP, Refusal, build, fatal, parse, rewrite};

impl Route {
    /// 선언에서 서비스 하나의 길을 만든다. 그 서비스에 적은 역할만 담긴다.
    pub fn for_service(names: &Names, manifest: &ValidManifest, service: &Ident) -> Self {
        Self {
            database: names.database(),
            logins: logins(names, manifest)
                .into_iter()
                .filter(|login| &login.service == service)
                .map(|login| (login.role.to_string(), login.name))
                .collect(),
        }
    }
}

/// 서비스 하나의 연결을 받는다. 멈추지 않는다.
///
/// `upstream` 은 DB 의 주소(`주소:포트`)다.
pub async fn serve(listener: TcpListener, upstream: String, route: Route) -> io::Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let (upstream, route) = (upstream.clone(), route.clone());
        tokio::spawn(async move {
            // 연결 하나가 깨져도 다른 연결은 그대로 간다. 서비스에게는 Postgres 의 오류 꾸러미로 이미 알렸다
            let _ = connection(client, &upstream, &route).await;
        });
    }
}

/// 길이 4바이트로 시작하는 첫 꾸러미를 읽는다.
async fn read_first(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let length = u32::from_be_bytes(head) as usize;
    if !(8..=MAX_STARTUP).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "첫 꾸러미의 길이가 맞지 않습니다",
        ));
    }
    let mut packet = head.to_vec();
    packet.resize(length, 0);
    client.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

/// 종류 1바이트와 길이 4바이트로 시작하는 꾸러미 하나를 읽는다.
async fn read_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 5];
    stream.read_exact(&mut head).await?;
    let length = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if !(4..=MAX_STARTUP).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DB 의 첫 답이 너무 깁니다",
        ));
    }
    let mut message = head.to_vec();
    message.resize(length + 1, 0);
    stream.read_exact(&mut message[5..]).await?;
    Ok(message)
}

async fn refuse(client: &mut TcpStream, sqlstate: &str, message: &str) -> io::Result<()> {
    client.write_all(&fatal(sqlstate, message)).await?;
    client.shutdown().await
}

async fn connection(mut client: TcpStream, upstream: &str, route: &Route) -> io::Result<()> {
    let (version, params) = loop {
        let packet = read_first(&mut client).await?;
        match parse(&packet) {
            Ok(First::Encryption) => client.write_all(b"N").await?,
            Ok(First::Cancel(packet)) => {
                // 취소 요청은 답이 없다. 꾸러미째 DB 에 전하고 닫는다
                let mut server = TcpStream::connect(upstream).await?;
                server.write_all(&packet).await?;
                return server.shutdown().await;
            }
            Ok(First::Startup { version, params }) => break (version, params),
            Err(_) => {
                return refuse(&mut client, "08P01", "연결의 첫 꾸러미를 읽지 못했습니다").await;
            }
        }
    };

    let params = match rewrite(&params, route) {
        Ok(params) => params,
        Err(Refusal::NoUser) => {
            return refuse(
                &mut client,
                "28000",
                "업무 역할의 이름을 사용자 자리에 적어 주세요",
            )
            .await;
        }
        Err(Refusal::RoleNotAllowed) => {
            return refuse(
                &mut client,
                "28000",
                "이 서비스는 그 역할로 DB 에 들어갈 수 없습니다. orbital.toml 의 서비스 roles 에 적힌 역할만 됩니다",
            )
            .await;
        }
    };

    let mut server = match TcpStream::connect(upstream).await {
        Ok(server) => server,
        Err(_) => return refuse(&mut client, "08006", "DB 에 닿지 못했습니다").await,
    };
    server.write_all(&build(version, &params)).await?;

    // DB 의 첫 답을 본다. 들여보냈다는 답만 서비스에게 넘긴다
    loop {
        let message = read_message(&mut server).await?;
        match message[0] {
            // 인증의 답. 뒤의 4바이트가 0 이면 들여보낸 것이다
            b'R' if message.len() >= 9 && message[5..9] == [0, 0, 0, 0] => {
                client.write_all(&message).await?;
                break;
            }
            b'R' => {
                return refuse(
                    &mut client,
                    "28000",
                    "DB 가 proxy 의 연결을 믿지 않습니다. 레이어의 설정을 확인해야 합니다",
                )
                .await;
            }
            // 프로토콜 버전을 맞추자는 답. 그대로 넘기고 다음 답을 기다린다
            b'v' => client.write_all(&message).await?,
            // 오류. 그대로 넘기고 닫는다
            _ => {
                client.write_all(&message).await?;
                return client.shutdown().await;
            }
        }
    }

    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .map(|_| ())
}
