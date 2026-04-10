use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Current encryption format version.
pub const FORMAT_VERSION: u32 = 2;

/// Supported format versions for backward compatibility.
pub const SUPPORTED_FORMAT_VERSIONS: &[u32] = &[1, 2];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub argon2: Argon2Config,
    pub encryption: EncryptionConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    /// Memory cost in KiB (default: 19456 = 19 MiB)
    pub m_cost: u32,
    /// Time cost / iterations (default: 2)
    pub t_cost: u32,
    /// Parallelism (default: 1)
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Maximum file size in bytes (default: 2 GiB)
    pub max_file_size: u64,
    /// Enable compression before encryption (default: true)
    pub compress: bool,
    /// Compression level 0-9 (default: 6)
    pub compression_level: u32,
    /// Chunk size for streaming encryption in bytes (default: 64 MiB)
    pub stream_chunk_size: usize,
    /// Threshold above which streaming mode is used (default: 100 MiB)
    pub stream_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging (default: true)
    pub enabled: bool,
    /// Path to audit log file
    pub log_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            argon2: Argon2Config {
                m_cost: 19456,
                t_cost: 2,
                p_cost: 1,
            },
            encryption: EncryptionConfig {
                max_file_size: 2 * 1024 * 1024 * 1024, // 2 GiB
                compress: true,
                compression_level: 6,
                stream_chunk_size: 64 * 1024 * 1024, // 64 MiB
                stream_threshold: 100 * 1024 * 1024,  // 100 MiB
            },
            audit: AuditConfig {
                enabled: true,
                log_file: "encryptor_audit.log".to_string(),
            },
        }
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_or_default() -> Self {
        let config_paths = [
            PathBuf::from("encryptor.toml"),
            dirs_config_path(),
        ];

        for path in &config_paths {
            if path.exists() {
                if let Ok(config) = Self::load(path) {
                    return config;
                }
            }
        }

        Config::default()
    }

    pub fn save_default<P: AsRef<Path>>(path: P) -> Result<(), anyhow::Error> {
        let config = Config::default();
        let content = toml::to_string_pretty(&config)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

fn dirs_config_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
    {
        PathBuf::from(home).join(".config").join("file-encryptor").join("config.toml")
    } else {
        PathBuf::from("encryptor.toml")
    }
}
