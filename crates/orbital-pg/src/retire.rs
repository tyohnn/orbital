//! 선언에서 뺀 역할을 걷는다.
//!
//! 승격에서 새 release 의 선언에 없는 이 인스턴스의 묶음과 로그인(core 의 [`stale_roles`])을 지운다. 걷기 전에 그 역할이 아무것의
//! 주인도 아닌지 본다. 주인인 것이 있으면 걷지 않고 까닭을 돌려준다(그 객체를 함께 지우지 않는다). 권한만 남아 있으면 그 권한을
//! 걷고(`DROP OWNED BY`, 주인인 것이 없으니 권한만 걷힌다) 역할을 지운다. 권한은 운영 DB 와 되돌릴 지점처럼 이 인스턴스의
//! database 에만 있어야 한다. 앞의 release 로 되돌릴 때는 레이어가 그 선언으로 다시 세운다(`provision` · `grant`).

use orbital_core::manifest::ValidManifest;
use orbital_core::plan::{Names, stale_roles};

use crate::{Admin, Error, pg, quote};

impl Admin {
    /// 선언에서 뺀 이 인스턴스의 역할.
    pub fn stale(&mut self, names: &Names, manifest: &ValidManifest) -> Result<Vec<String>, Error> {
        let prefix = format!("{}_", names.prefix());
        let existing: Vec<String> = self
            .cluster
            .query(
                "SELECT rolname FROM pg_roles WHERE left(rolname, length($1)) = $1 ORDER BY 1",
                &[&prefix],
            )
            .map_err(pg("역할의 목록을 읽"))?
            .iter()
            .map(|row| row.get(0))
            .collect();
        Ok(stale_roles(names, manifest, &existing))
    }

    /// 선언에서 뺀 역할 가운데 아직 무엇의 주인인 것. 하나라도 있으면 승격을 멈춘다(바꾸기 전에 본다).
    pub fn stale_owners(
        &mut self,
        names: &Names,
        manifest: &ValidManifest,
    ) -> Result<Vec<String>, Error> {
        let mut owners = Vec::new();
        for role in self.stale(names, manifest)? {
            if self.owns_anything(&role)? {
                owners.push(role);
            }
        }
        Ok(owners)
    }

    fn owns_anything(&mut self, role: &str) -> Result<bool, Error> {
        let owned: i64 = self
            .cluster
            .query_one(
                "SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid \
                 WHERE d.refclassid = 'pg_authid'::regclass AND d.deptype = 'o' AND r.rolname = $1",
                &[&role],
            )
            .map_err(pg("역할이 가진 것을 찾"))?
            .get(0);
        Ok(owned > 0)
    }

    /// 선언에서 뺀 역할을 걷는다. 걷은 역할의 이름을 돌려준다. 주인인 것이 있거나 이 인스턴스 밖에 권한이 있으면 걷지 않고 멈춘다.
    pub fn retire(
        &mut self,
        names: &Names,
        manifest: &ValidManifest,
    ) -> Result<Vec<String>, Error> {
        let stale = self.stale(names, manifest)?;
        let ours = self.databases(names)?;
        for role in &stale {
            if self.owns_anything(role)? {
                return Err(Error::RoleOwnsObjects { role: role.clone() });
            }
            // 권한이 남은 database(공유 객체의 권한은 어느 database 에서든 걷힌다)
            let holding: Vec<(String, bool)> = self
                .cluster
                .query(
                    "SELECT DISTINCT db.datname, db.datallowconn FROM pg_shdepend d \
                     JOIN pg_roles r ON r.oid = d.refobjid JOIN pg_database db ON db.oid = d.dbid \
                     WHERE d.refclassid = 'pg_authid'::regclass AND r.rolname = $1",
                    &[&role],
                )
                .map_err(pg("역할의 권한이 남은 자리를 찾"))?
                .iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect();
            if holding.iter().any(|(database, _)| !ours.contains(database)) {
                return Err(Error::RoleUsedElsewhere { role: role.clone() });
            }
            let mut places = holding;
            if !places
                .iter()
                .any(|(database, _)| *database == names.database())
            {
                places.push((names.database(), true));
            }
            for (database, open) in places {
                // 닫아 둔 되돌릴 지점은 잠깐 열어 권한을 걷고 다시 닫는다
                if !open {
                    self.open(&database, true)?;
                }
                let dropped = self.database(&database).and_then(|mut client| {
                    client
                        .batch_execute(&format!("DROP OWNED BY {}", quote(role)))
                        .map_err(pg("역할의 권한을 걷"))
                });
                if !open {
                    self.open(&database, false)?;
                }
                dropped?;
            }
            self.cluster
                .batch_execute(&format!("DROP ROLE {}", quote(role)))
                .map_err(pg("역할을 지우"))?;
        }
        Ok(stale)
    }
}
