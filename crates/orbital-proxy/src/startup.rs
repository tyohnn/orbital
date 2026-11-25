//! Postgres 연결의 첫 꾸러미를 읽고 다시 쓴다. 순수한 바이트 다루기다.
//!
//! 서비스는 업무 역할의 이름을 사용자 자리에 적어 붙는다. proxy 는 그 이름을 그 서비스의 로그인으로 바꾸고, database 는 무엇을 적었든
//! 인스턴스의 것으로 바꾼다. 연결을 시작하며 실어 보낸 설정은 받을 것만 고른다. 역할을 바꾸거나 복제 연결을 여는 설정은 버린다.

use std::collections::BTreeMap;

/// 첫 꾸러미의 상한. Postgres 도 10000 바이트에서 끊는다.
pub const MAX_STARTUP: usize = 10_000;

const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
const PROTOCOL_3: u32 = 3;

/// 서비스가 연결을 시작하며 실어 보내도 되는 설정. 여기에 없는 것은 DB 에 전하지 않는다.
///
/// `options`(임의의 설정을 싣는 자리), `replication`(복제 연결), `role` · `session_authorization`(역할 바꾸기)이 빠져 있다.
const ALLOWED: [&str; 6] = [
    "client_encoding",
    "application_name",
    "datestyle",
    "timezone",
    "extra_float_digits",
    "intervalstyle",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum First {
    /// 암호화를 묻는다. proxy 는 서비스와 같은 기계 안에서만 듣기 때문에 받지 않는다고 답한다.
    Encryption,
    /// 돌고 있는 질의를 멈춰 달라는 요청. 꾸러미째 DB 에 전한다.
    Cancel(Vec<u8>),
    Startup {
        version: u32,
        params: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    Length,
    Version,
    Params,
}

/// 첫 꾸러미 전체(길이 4바이트를 포함한다)를 읽는다.
pub fn parse(packet: &[u8]) -> Result<First, Malformed> {
    if packet.len() < 8 || packet.len() > MAX_STARTUP {
        return Err(Malformed::Length);
    }
    let length = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
    if length != packet.len() {
        return Err(Malformed::Length);
    }
    let code = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    match code {
        SSL_REQUEST | GSSENC_REQUEST => Ok(First::Encryption),
        CANCEL_REQUEST => Ok(First::Cancel(packet.to_vec())),
        version if version >> 16 == PROTOCOL_3 => {
            let mut params = Vec::new();
            let mut fields = packet[8..].split(|byte| *byte == 0);
            loop {
                let key = fields.next().ok_or(Malformed::Params)?;
                if key.is_empty() {
                    break;
                }
                let value = fields.next().ok_or(Malformed::Params)?;
                let text =
                    |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| Malformed::Params);
                params.push((text(key)?, text(value)?));
            }
            Ok(First::Startup { version, params })
        }
        _ => Err(Malformed::Version),
    }
}

/// 시작 꾸러미를 만든다.
pub fn build(version: u32, params: &[(String, String)]) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    for (key, value) in params {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut packet = (u32::try_from(body.len() + 4).expect("상한보다 작다"))
        .to_be_bytes()
        .to_vec();
    packet.extend(body);
    packet
}

/// 서비스 하나의 연결이 어디로 가는가. 듣는 자리마다 하나씩 둔다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// 인스턴스의 database.
    pub database: String,
    /// 업무 역할의 이름 → 이 서비스가 그 역할로 들어갈 때의 로그인.
    pub logins: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NoUser,
    /// 이 서비스의 선언에 없는 역할이다.
    RoleNotAllowed,
}

/// 서비스가 보낸 설정을 DB 에 보낼 설정으로 바꾼다.
pub fn rewrite(
    params: &[(String, String)],
    route: &Route,
) -> Result<Vec<(String, String)>, Refusal> {
    let role = params
        .iter()
        .find(|(key, _)| key == "user")
        .map(|(_, value)| value)
        .ok_or(Refusal::NoUser)?;
    let login = route.logins.get(role).ok_or(Refusal::RoleNotAllowed)?;
    let mut rewritten = vec![
        ("user".to_owned(), login.clone()),
        ("database".to_owned(), route.database.clone()),
    ];
    for (key, value) in params {
        if ALLOWED.contains(&key.to_ascii_lowercase().as_str()) {
            rewritten.push((key.clone(), value.clone()));
        }
    }
    Ok(rewritten)
}

/// 연결을 닫으며 서비스에게 보내는 오류. Postgres 의 오류 꾸러미 모양이라 어떤 드라이버든 그대로 읽는다.
pub fn fatal(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut packet = vec![b'E'];
    packet.extend(
        u32::try_from(body.len() + 4)
            .expect("짧은 글이다")
            .to_be_bytes(),
    );
    packet.extend(body);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    fn route() -> Route {
        Route {
            database: "i_k3f9x2ab".to_owned(),
            logins: [(
                "employee".to_owned(),
                "i_k3f9x2ab_s_web_employee".to_owned(),
            )]
            .into(),
        }
    }

    #[test]
    fn 시작_꾸러미를_만들고_다시_읽으면_같은_설정이_나온다() {
        let params = vec![
            pair("user", "employee"),
            pair("database", "app"),
            pair("application_name", "web"),
        ];
        assert_eq!(
            parse(&build(196_608, &params)),
            Ok(First::Startup {
                version: 196_608,
                params
            })
        );
    }

    #[test]
    fn 암호화를_묻는_꾸러미와_취소_요청을_알아본다() {
        let ssl = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(parse(&ssl), Ok(First::Encryption));
        let cancel = [0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(parse(&cancel), Ok(First::Cancel(cancel.to_vec())));
    }

    #[test]
    fn 길이가_맞지_않거나_상한을_넘는_꾸러미는_받지_않는다() {
        assert_eq!(parse(&[0, 0, 0, 9, 0, 3, 0, 0]), Err(Malformed::Length));
        assert_eq!(parse(&[0, 0, 0, 4]), Err(Malformed::Length));
        let mut huge = build(196_608, &[pair("user", &"x".repeat(MAX_STARTUP))]);
        huge.truncate(MAX_STARTUP + 1);
        assert_eq!(parse(&huge), Err(Malformed::Length));
    }

    #[test]
    fn 모르는_버전과_끝나지_않은_설정은_받지_않는다() {
        assert_eq!(parse(&[0, 0, 0, 8, 0, 2, 0, 0]), Err(Malformed::Version));
        // 값이 없는 열쇠
        assert_eq!(
            parse(&[0, 0, 0, 12, 0, 3, 0, 0, b'u', b's', b'e', b'r']),
            Err(Malformed::Params)
        );
    }

    #[test]
    fn 업무_역할의_이름은_그_서비스의_로그인으로_바뀐다() {
        let rewritten = rewrite(&[pair("user", "employee")], &route()).unwrap();
        assert_eq!(
            rewritten,
            vec![
                pair("user", "i_k3f9x2ab_s_web_employee"),
                pair("database", "i_k3f9x2ab")
            ]
        );
    }

    #[test]
    fn database_는_무엇을_적었든_인스턴스의_것으로_바뀐다() {
        let rewritten = rewrite(
            &[pair("user", "employee"), pair("database", "i_zzzzzzzz")],
            &route(),
        )
        .unwrap();
        assert!(rewritten.contains(&pair("database", "i_k3f9x2ab")));
        assert!(!rewritten.iter().any(|(_, value)| value == "i_zzzzzzzz"));
    }

    #[test]
    fn 서비스의_선언에_없는_역할은_거절한다() {
        assert_eq!(
            rewrite(&[pair("user", "payroll_admin")], &route()),
            Err(Refusal::RoleNotAllowed)
        );
        // 로그인의 이름을 직접 적어도 받지 않는다. 받는 것은 업무 역할의 이름뿐이다
        assert_eq!(
            rewrite(&[pair("user", "i_k3f9x2ab_s_web_employee")], &route()),
            Err(Refusal::RoleNotAllowed)
        );
        assert_eq!(
            rewrite(&[pair("user", "postgres")], &route()),
            Err(Refusal::RoleNotAllowed)
        );
        assert_eq!(
            rewrite(&[pair("database", "app")], &route()),
            Err(Refusal::NoUser)
        );
    }

    #[test]
    fn 역할을_바꾸거나_복제_연결을_여는_설정은_버린다() {
        let params = [
            pair("user", "employee"),
            pair("options", "-c role=i_k3f9x2ab_r_payroll_admin"),
            pair("replication", "database"),
            pair("role", "i_k3f9x2ab_owner"),
            pair("session_authorization", "postgres"),
            pair("application_name", "web"),
            pair("TimeZone", "Asia/Seoul"),
        ];
        let rewritten = rewrite(&params, &route()).unwrap();
        let keys: Vec<&str> = rewritten.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            vec!["user", "database", "application_name", "TimeZone"]
        );
    }

    #[test]
    fn 닫는_오류는_postgres_의_오류_꾸러미_모양이다() {
        let packet = fatal("28000", "거절");
        assert_eq!(packet[0], b'E');
        let length = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        assert_eq!(length, packet.len() - 1);
        assert!(packet.windows(6).any(|window| window == b"C28000"));
        assert_eq!(packet.last(), Some(&0));
    }
}
