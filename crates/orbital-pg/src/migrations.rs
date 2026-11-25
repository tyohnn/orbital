//! 이름이 붙은 마이그레이션. 이미 돈 것은 다시 돌리지 않는다.
//!
//! 돈 마이그레이션의 이름은 인스턴스의 database 안(`orbital.migration`)에 적는다. 마이그레이션과 그 기록이 한 트랜잭션에 든다.
//! 그래서 database 를 복제한 사본과 되돌릴 지점도 자기가 어디까지 돌았는지를 스스로 안다.

use orbital_core::plan::Names;

use crate::{Admin, Error, pg, quote};

impl Admin {
    /// 이미 돈 마이그레이션의 이름을 순서대로 돌려준다.
    pub fn applied(&mut self, names: &Names) -> Result<Vec<String>, Error> {
        let mut client = self.database(&names.database())?;
        let rows = client
            .query("SELECT name FROM orbital.migration ORDER BY name", &[])
            .map_err(pg("돈 마이그레이션을 읽"))?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    /// 아직 돌지 않은 마이그레이션만 준 순서대로 돌리고, 돌린 이름을 돌려준다. `scripts` 는 (이름, SQL)이다.
    ///
    /// 마이그레이션 역할로 들어가 소유자가 되어 돌린다. 하나가 실패하면 거기서 멈추고, 앞에서 돈 것은 남는다.
    pub fn migrate_named(
        &mut self,
        names: &Names,
        scripts: &[(&str, &str)],
    ) -> Result<Vec<String>, Error> {
        let done = self.applied(names)?;
        let mut client = self
            .connect_as(&names.database(), &names.migrator())
            .map_err(pg("마이그레이션 역할로 붙"))?;
        client
            .batch_execute(&format!("SET ROLE {}", quote(&names.owner())))
            .map_err(pg("소유자가 되"))?;
        let mut ran = Vec::new();
        for (name, sql) in scripts {
            if done.iter().any(|applied| applied == name) {
                continue;
            }
            let mut transaction = client.transaction().map_err(pg("마이그레이션을 시작"))?;
            transaction
                .batch_execute(sql)
                .map_err(pg("마이그레이션을 실행"))?;
            transaction
                .execute("INSERT INTO orbital.migration (name) VALUES ($1)", &[name])
                .map_err(pg("마이그레이션의 이름을 적"))?;
            transaction.commit().map_err(pg("마이그레이션을 마무리"))?;
            ran.push((*name).to_owned());
        }
        Ok(ran)
    }

    /// 준 것 가운데 아직 돌지 않은 마이그레이션의 이름.
    pub fn pending(&mut self, names: &Names, all: &[&str]) -> Result<Vec<String>, Error> {
        let done = self.applied(names)?;
        Ok(all
            .iter()
            .filter(|name| !done.iter().any(|applied| applied == *name))
            .map(|name| (*name).to_owned())
            .collect())
    }
}
