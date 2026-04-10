use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use chrono::Local;

use crate::config::AuditConfig;

pub enum AuditAction {
    Encrypt,
    Decrypt,
    EncryptDir,
    DecryptDir,
    Sign,
    Verify,
    GenerateKeys,
    ReEncrypt,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::Encrypt => write!(f, "ENCRYPT"),
            AuditAction::Decrypt => write!(f, "DECRYPT"),
            AuditAction::EncryptDir => write!(f, "ENCRYPT_DIR"),
            AuditAction::DecryptDir => write!(f, "DECRYPT_DIR"),
            AuditAction::Sign => write!(f, "SIGN"),
            AuditAction::Verify => write!(f, "VERIFY"),
            AuditAction::GenerateKeys => write!(f, "GENERATE_KEYS"),
            AuditAction::ReEncrypt => write!(f, "RE_ENCRYPT"),
        }
    }
}

pub struct AuditLogger {
    config: AuditConfig,
}

impl AuditLogger {
    pub fn new(config: &AuditConfig) -> Self {
        AuditLogger {
            config: config.clone(),
        }
    }

    pub fn log(&self, action: AuditAction, target: &str, success: bool, details: &str) {
        if !self.config.enabled {
            return;
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let status = if success { "OK" } else { "FAIL" };
        let line = format!("[{}] {} {} target={} {}\n", timestamp, action, status, target, details);

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.log_file)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}
