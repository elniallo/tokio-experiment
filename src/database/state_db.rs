use std::error::Error;
use std::path::PathBuf;

use crate::account::db_state::DBState;
use crate::database::IDB;
use crate::traits::{Decode, Encode, Exception};

use rocksdb::DB as RocksDB;

use starling::traits::Database;

impl<DBType> Database for StateDB<DBType>
where
    DBType: IDB,
{
    type NodeType = DBState;
    type EntryType = (Vec<u8>, Self::NodeType);

    fn open(_path: &PathBuf) -> Result<StateDB<DBType, Self::EntryType>, Box<Error>> {
        return Err(Box::new(Exception::new(
            "Open the database using new, not open",
        )));
    }

    fn get_node(&self, key: &[u8]) -> Result<Option<Self::NodeType>, Box<Error>> {
        let bytes = self.database._get(&key)?;
        Ok(Some(Self::NodeType::decode(&bytes)?))
    }

    fn insert(&mut self, key: &[u8], value: &Self::NodeType) -> Result<(), Box<Error>> {
        self.pending_inserts.push((key.to_vec(), value.clone()));
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Box<Error>> {
        self.database.delete(key)?;
        Ok(())
    }

    fn batch_write(&mut self) -> Result<(), Box<Error>> {
        let mut batch = Vec::with_capacity(self.pending_inserts.len());
        while self.pending_inserts.len() > 0 {
            let entry = self.pending_inserts.remove(0);
            let key = entry.0;
            let value = entry.1;
            batch.push((key, value.encode()?));
        }
        self.database.write_batch(batch)?;
        Ok(())
    }
}

pub struct StateDB<DatabaseType = RocksDB, EntryType = (Vec<u8>, DBState)> {
    database: DatabaseType,
    pending_inserts: Vec<EntryType>,
}

impl<DatabaseType, EntryType, OptionType> StateDB<DatabaseType, EntryType>
where
    DatabaseType: IDB<OptionType = OptionType>,
{
    pub fn new(
        path: PathBuf,
        options: Option<OptionType>,
    ) -> Result<StateDB<DatabaseType, EntryType>, Box<Error>> {
        let database = DatabaseType::open(path, options)?;
        let pending_inserts = Vec::with_capacity(40000);
        Ok(StateDB {
            database,
            pending_inserts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::mock::RocksDBMock;

    #[test]
    fn it_opens_a_state_db() {
        let path = PathBuf::new();
        let _state_db: StateDB<RocksDBMock> = StateDB::new(path, None).unwrap();
    }
}
