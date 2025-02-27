#[derive(Clone, Debug)]
pub struct Config {
    pub storage: StorageConfig,
    pub num_pub_rand: u64
}

#[derive(Clone, Debug)]
pub enum DatabaseBackend {
    RocksDB,
    Memory,
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub backend: DatabaseBackend,
    pub path: String,
    pub columns: u32,
}
