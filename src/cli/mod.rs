use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::path::PathBuf;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::crypto::{encrypt_file_with_config, decrypt_file_with_config};
use crate::signature::{
    generate_keypair, save_keypair, save_keypair_encrypted,
    load_keypair, load_keypair_encrypted,
    save_public_key, load_public_key,
    sign_file, verify_file,
};
use crate::format::EncryptedFile;
use crate::hardware::{get_device_fingerprint, validate_device_fingerprint};
use crate::security::{validate_password_strength, RateLimiter};
use crate::config::Config;
use crate::audit::{AuditLogger, AuditAction};

#[derive(Parser)]
#[command(name = "file-encryptor")]
#[command(about = "Universal file encryption system with advanced security features", version = "0.3.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file with password and optional device binding
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Password (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        bind_device: bool,
        #[arg(short = 'k', long)]
        private_key: Option<PathBuf>,
    },

    /// Decrypt a file with password
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Password (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        validate_device: bool,
        #[arg(short = 'k', long)]
        public_key: Option<PathBuf>,
    },

    /// Encrypt a directory (tar + encrypt)
    EncryptDir {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        bind_device: bool,
        #[arg(short = 'k', long)]
        private_key: Option<PathBuf>,
    },

    /// Decrypt a directory archive
    DecryptDir {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        validate_device: bool,
        #[arg(short = 'k', long)]
        public_key: Option<PathBuf>,
    },

    /// Re-encrypt a file with a new password
    ReEncrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Current password (omit to enter interactively)
        #[arg(long)]
        old_password: Option<String>,
        /// New password (omit to enter interactively)
        #[arg(long)]
        new_password: Option<String>,
    },

    /// Generate Ed25519 key pair
    GenerateKeys {
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
        #[arg(short, long, default_value = "key")]
        name: String,
        /// Passphrase to encrypt the private key file (omit for plaintext)
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Sign a file with private key
    Sign {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short = 'k', long)]
        private_key: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Passphrase if private key is encrypted
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Verify file signature with public key
    Verify {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short = 'k', long)]
        public_key: PathBuf,
        #[arg(short, long)]
        signature: PathBuf,
    },

    /// Show device fingerprint
    Fingerprint,

    /// Validate device fingerprint
    ValidateFingerprint {
        fingerprint: String,
    },

    /// Generate default configuration file
    InitConfig {
        #[arg(short, long, default_value = "encryptor.toml")]
        output: PathBuf,
    },

    /// Generate shell completions
    Completions {
        /// Shell type: bash, zsh, fish, powershell
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn prompt_password_encrypt() -> Result<String> {
    let password = rpassword::prompt_password("Enter encryption password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }
    Ok(password)
}

fn prompt_password_decrypt() -> Result<String> {
    Ok(rpassword::prompt_password("Enter decryption password: ")?)
}

fn validate_input_exists(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Input file not found: {:?}", path);
    }
    Ok(())
}

fn validate_dir_exists(path: &PathBuf) -> Result<()> {
    if !path.is_dir() {
        anyhow::bail!("Input is not a directory: {:?}", path);
    }
    Ok(())
}

fn create_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

fn archive_directory(dir_path: &PathBuf) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let mut archive = tar::Builder::new(buf);
    archive.append_dir_all(".", dir_path)?;
    Ok(archive.into_inner()?)
}

fn extract_archive(data: &[u8], output_dir: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;
    let mut archive = tar::Archive::new(data);
    archive.unpack(output_dir)?;
    Ok(())
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load_or_default();
    let audit = AuditLogger::new(&config.audit);
    let mut rate_limiter = RateLimiter::new(3, std::time::Duration::from_secs(60));

    match cli.command {
        Commands::Encrypt { input, output, password, bind_device, private_key } => {
            validate_input_exists(&input)?;

            let password = match password {
                Some(p) => p,
                None => prompt_password_encrypt()?,
            };
            if let Err(e) = validate_password_strength(&password) {
                eprintln!("Password rejected: {}", e);
                std::process::exit(1);
            }

            let pb = create_spinner("Encrypting file...");

            let keypair = if let Some(key_path) = private_key {
                Some(load_keypair(key_path)?)
            } else {
                None
            };

            let result = if let Some(keypair) = keypair {
                EncryptedFile::encrypt_and_sign(&input, &output, &password, &keypair, bind_device)
                    .map(|_| ())
                    .map_err(|e| e.into())
            } else {
                let device_id = if bind_device { Some(get_device_fingerprint()?) } else { None };
                encrypt_file_with_config(&input, &output, &password, device_id.as_deref(), &config)
                    .map_err(|e| e.into())
            };

            match &result {
                Ok(_) => {
                    pb.finish_with_message("File encrypted successfully!");
                    audit.log(AuditAction::Encrypt, &input.display().to_string(), true, "");
                }
                Err(e) => {
                    pb.finish_with_message(format!("Encryption failed: {}", e));
                    audit.log(AuditAction::Encrypt, &input.display().to_string(), false, &e.to_string());
                }
            }
            result?;
        }

        Commands::Decrypt { input, output, password, validate_device, public_key } => {
            validate_input_exists(&input)?;
            if rate_limiter.check_rate_limit().is_err() {
                eprintln!("Rate limit exceeded. Please wait and try again.");
                std::process::exit(1);
            }

            let password = match password {
                Some(p) => p,
                None => prompt_password_decrypt()?,
            };

            let pb = create_spinner("Decrypting file...");

            let result: Result<()> = if let Some(key_path) = public_key {
                let pk = load_public_key(key_path)?;
                let metadata = EncryptedFile::decrypt_and_verify(&input, &output, &password, &pk, validate_device)?;
                pb.finish_with_message("File decrypted and verified!");
                println!("Original filename: {}", metadata.original_filename);
                println!("File size: {} bytes", metadata.file_size);
                Ok(())
            } else {
                let device_id = if validate_device { Some(get_device_fingerprint()?) } else { None };
                decrypt_file_with_config(&input, &output, &password, device_id.as_deref(), &config)?;
                pb.finish_with_message("File decrypted successfully!");
                Ok(())
            };

            let success = result.is_ok();
            audit.log(AuditAction::Decrypt, &input.display().to_string(), success, "");
            result?;
        }

        Commands::EncryptDir { input, output, password, bind_device, private_key } => {
            validate_dir_exists(&input)?;

            let password = match password {
                Some(p) => p,
                None => prompt_password_encrypt()?,
            };
            if let Err(e) = validate_password_strength(&password) {
                eprintln!("Password rejected: {}", e);
                std::process::exit(1);
            }

            let pb = create_spinner("Archiving directory...");
            let archive_data = archive_directory(&input)?;
            let temp_tar = tempfile::NamedTempFile::new()?;
            std::fs::write(temp_tar.path(), &archive_data)?;

            pb.set_message("Encrypting archive...".to_string());

            if let Some(key_path) = private_key {
                let keypair = load_keypair(key_path)?;
                EncryptedFile::encrypt_and_sign(temp_tar.path(), &output, &password, &keypair, bind_device)?;
            } else {
                let device_id = if bind_device { Some(get_device_fingerprint()?) } else { None };
                encrypt_file_with_config(temp_tar.path(), &output, &password, device_id.as_deref(), &config)?;
            }

            pb.finish_with_message("Directory encrypted successfully!");
            audit.log(AuditAction::EncryptDir, &input.display().to_string(), true, "");
        }

        Commands::DecryptDir { input, output, password, validate_device, public_key } => {
            validate_input_exists(&input)?;
            if rate_limiter.check_rate_limit().is_err() {
                eprintln!("Rate limit exceeded. Please wait and try again.");
                std::process::exit(1);
            }

            let password = match password {
                Some(p) => p,
                None => prompt_password_decrypt()?,
            };

            let pb = create_spinner("Decrypting archive...");
            let temp_tar = tempfile::NamedTempFile::new()?;

            if let Some(key_path) = public_key {
                let pk = load_public_key(key_path)?;
                EncryptedFile::decrypt_and_verify(&input, temp_tar.path(), &password, &pk, validate_device)?;
            } else {
                let device_id = if validate_device { Some(get_device_fingerprint()?) } else { None };
                decrypt_file_with_config(&input, temp_tar.path(), &password, device_id.as_deref(), &config)?;
            }

            pb.set_message("Extracting archive...".to_string());
            let tar_data = std::fs::read(temp_tar.path())?;
            extract_archive(&tar_data, &output)?;

            pb.finish_with_message("Directory decrypted and extracted!");
            audit.log(AuditAction::DecryptDir, &input.display().to_string(), true, "");
        }

        Commands::ReEncrypt { input, output, old_password, new_password } => {
            validate_input_exists(&input)?;

            let old_pass = match old_password {
                Some(p) => p,
                None => rpassword::prompt_password("Enter current password: ")?,
            };
            let new_pass = match new_password {
                Some(p) => p,
                None => {
                    let p = rpassword::prompt_password("Enter new password: ")?;
                    let c = rpassword::prompt_password("Confirm new password: ")?;
                    if p != c { anyhow::bail!("New passwords do not match"); }
                    p
                }
            };

            if let Err(e) = validate_password_strength(&new_pass) {
                eprintln!("New password rejected: {}", e);
                std::process::exit(1);
            }

            let pb = create_spinner("Re-encrypting file...");

            // Decrypt with old password to a temp file, then re-encrypt with new
            let temp = tempfile::NamedTempFile::new()?;
            decrypt_file_with_config(&input, temp.path(), &old_pass, None, &config)?;
            encrypt_file_with_config(temp.path(), &output, &new_pass, None, &config)?;

            pb.finish_with_message("File re-encrypted with new password!");
            audit.log(AuditAction::ReEncrypt, &input.display().to_string(), true, "");
        }

        Commands::GenerateKeys { output_dir, name, passphrase } => {
            let pb = create_spinner("Generating Ed25519 key pair...");

            let keypair = generate_keypair()?;
            let private_key_path = output_dir.join(format!("{}_private.json", name));
            let public_key_path = output_dir.join(format!("{}_public.json", name));

            save_keypair_encrypted(&keypair, &private_key_path, passphrase.as_deref())?;
            save_public_key(&keypair.public_key_only(), &public_key_path)?;

            pb.finish_with_message("Key pair generated!");
            println!("Private key: {:?}", private_key_path);
            println!("Public key: {:?}", public_key_path);
            if passphrase.is_some() {
                println!("Private key is encrypted with your passphrase.");
            }
            audit.log(AuditAction::GenerateKeys, &private_key_path.display().to_string(), true, "");
        }

        Commands::Sign { file, private_key, output, passphrase } => {
            validate_input_exists(&file)?;
            let pb = create_spinner("Signing file...");

            let keypair = load_keypair_encrypted(private_key, passphrase.as_deref())?;
            let signature = sign_file(&file, &keypair)?;

            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("sig");
                path
            });

            std::fs::write(&output_path, &signature)?;
            pb.finish_with_message("File signed!");
            println!("Signature: {:?}", output_path);
            audit.log(AuditAction::Sign, &file.display().to_string(), true, "");
        }

        Commands::Verify { file, public_key, signature } => {
            validate_input_exists(&file)?;
            let pb = create_spinner("Verifying...");

            let pk = load_public_key(public_key)?;
            let sig_bytes = std::fs::read(signature)?;
            let is_valid = verify_file(&file, &pk, &sig_bytes)?;

            if is_valid {
                pb.finish_with_message("Signature verification successful!");
                audit.log(AuditAction::Verify, &file.display().to_string(), true, "");
            } else {
                pb.finish_with_message("Signature verification FAILED!");
                audit.log(AuditAction::Verify, &file.display().to_string(), false, "invalid signature");
                std::process::exit(1);
            }
        }

        Commands::Fingerprint => {
            println!("Device fingerprint: {}", get_device_fingerprint()?);
        }

        Commands::ValidateFingerprint { fingerprint } => {
            if validate_device_fingerprint(&fingerprint)? {
                println!("Device fingerprint is valid!");
            } else {
                println!("Device fingerprint validation FAILED!");
                std::process::exit(1);
            }
        }

        Commands::InitConfig { output } => {
            Config::save_default(&output)?;
            println!("Configuration saved to: {:?}", output);
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "file-encryptor", &mut std::io::stdout());
        }
    }

    Ok(())
}
