//! 이름. 선언 파일에 적힌 이름은 SQL 과 주소에 그대로 들어가므로, 값이 될 수 없는 이름은 만들지 못하게 한다.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong { max: usize },
    BadCharacter,
    Reserved,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "이름이 비어 있습니다"),
            Self::TooLong { max } => write!(f, "이름은 {max}자까지입니다"),
            Self::BadCharacter => write!(f, "쓸 수 없는 글자가 있습니다"),
            Self::Reserved => write!(f, "레이어가 쓰는 이름이라 선언할 수 없습니다"),
        }
    }
}

/// 서비스 · 스키마 · 역할 · 표의 이름. 영문 소문자로 시작하고 소문자 · 숫자 · 밑줄만 쓴다.
///
/// 글자를 이렇게 좁혀 두면 SQL 에 넣을 때 따옴표를 깨는 이름이 생기지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ident(String);

impl Ident {
    pub const MAX: usize = 24;

    /// 레이어와 Postgres 가 쓰는 이름. 고객의 선언이 이 자리를 차지하지 못한다.
    const RESERVED: [&'static str; 5] =
        ["public", "orbital", "information_schema", "postgres", "rls"];

    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if text.len() > Self::MAX {
            return Err(NameError::TooLong { max: Self::MAX });
        }
        let mut chars = text.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !first_ok || !rest_ok {
            return Err(NameError::BadCharacter);
        }
        if text.starts_with("pg_") || Self::RESERVED.contains(&text) {
            return Err(NameError::Reserved);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Ident {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).map_err(|error| format!("`{text}`: {error}"))
    }
}

impl From<Ident> for String {
    fn from(ident: Ident) -> Self {
        ident.0
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 인스턴스의 식별자. 뜻이 없는 글자열이다.
///
/// database 와 역할의 이름은 같은 클러스터의 다른 인스턴스에게도 보이므로, 고객을 짐작할 수 있는 말을 담지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceId(String);

impl InstanceId {
    pub const MIN: usize = 8;
    pub const MAX: usize = 12;

    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.len() < Self::MIN {
            return Err(NameError::Empty);
        }
        if text.len() > Self::MAX {
            return Err(NameError::TooLong { max: Self::MAX });
        }
        if !text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(NameError::BadCharacter);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InstanceId {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).map_err(|error| format!("`{text}`: {error}"))
    }
}

impl From<InstanceId> for String {
    fn from(id: InstanceId) -> Self {
        id.0
    }
}

/// 비밀의 이름. 값은 레이어가 갖고, 코드에는 이름만 적는다.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl SecretName {
    pub const MAX: usize = 48;

    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if text.len() > Self::MAX {
            return Err(NameError::TooLong { max: Self::MAX });
        }
        let mut chars = text.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_uppercase());
        let rest_ok = chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if !first_ok || !rest_ok {
            return Err(NameError::BadCharacter);
        }
        if text.starts_with("ORBITAL_") {
            return Err(NameError::Reserved);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretName {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).map_err(|error| format!("`{text}`: {error}"))
    }
}

impl From<SecretName> for String {
    fn from(name: SecretName) -> Self {
        name.0
    }
}

/// 스키마 안의 표 하나.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TableRef {
    pub schema: Ident,
    pub table: Ident,
}

impl fmt::Display for TableRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.schema, self.table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 이름은_소문자로_시작하고_소문자_숫자_밑줄만_쓴다() {
        assert!(Ident::parse("payroll_2").is_ok());
        assert_eq!(Ident::parse("Payroll"), Err(NameError::BadCharacter));
        assert_eq!(Ident::parse("2payroll"), Err(NameError::BadCharacter));
        assert_eq!(Ident::parse("pay-roll"), Err(NameError::BadCharacter));
        assert_eq!(Ident::parse("pay\"roll"), Err(NameError::BadCharacter));
        assert_eq!(Ident::parse(""), Err(NameError::Empty));
    }

    #[test]
    fn 이름은_24자까지_받고_25자는_받지_않는다() {
        assert!(Ident::parse(&"a".repeat(24)).is_ok());
        assert_eq!(
            Ident::parse(&"a".repeat(25)),
            Err(NameError::TooLong { max: 24 })
        );
    }

    #[test]
    fn 레이어와_postgres_가_쓰는_이름은_선언하지_못한다() {
        for reserved in [
            "public",
            "orbital",
            "information_schema",
            "postgres",
            "rls",
            "pg_catalog",
            "pg_x",
        ] {
            assert_eq!(
                Ident::parse(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
        }
        assert!(Ident::parse("pgx").is_ok());
    }

    #[test]
    fn 인스턴스_식별자는_8자에서_12자의_소문자와_숫자다() {
        assert!(InstanceId::parse("k3f9x2ab").is_ok());
        assert!(InstanceId::parse("k3f9x2abq7m1").is_ok());
        assert!(InstanceId::parse("k3f9x2a").is_err());
        assert!(InstanceId::parse("k3f9x2abq7m1z").is_err());
        assert!(InstanceId::parse("acme_corp").is_err());
    }

    #[test]
    fn 비밀의_이름은_대문자로_적고_레이어의_머리말은_쓰지_못한다() {
        assert!(SecretName::parse("BANK_API_KEY").is_ok());
        assert_eq!(
            SecretName::parse("bank_api_key"),
            Err(NameError::BadCharacter)
        );
        assert_eq!(SecretName::parse("ORBITAL_TOKEN"), Err(NameError::Reserved));
    }
}
