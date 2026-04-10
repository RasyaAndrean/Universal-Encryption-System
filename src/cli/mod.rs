use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::crypto::{encrypt_file, decrypt_file};
use crate::signature::{generate_keypair, save_keypair, load_keypair, save_public_key, load_public_key, sign_file, verify_file};
use crate::format::EncryptedFile;
use crate::hardware::{get_device_fingerprint, validate_device_fingerprint};
use crate::security::{validate_password_strength, RateLimiter};
use crate::config::Config;

#[derive(Parser)]
#[command(name = "file-encryptor")]
#[command(about = "Universal file encryption system with advanced security features", version = "0.2.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file with password and optional device binding
    Encrypt {
        /// Input file or directory to encrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output encrypted file path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for encryption (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Bind encryption to current device
        #[arg(long)]
        bind_device: bool,

        /// Path to private key for signing (optional)
        #[arg(short = 'k', long)]
        private_key: Option<PathBuf>,
    },

    /// Decrypt a file with password
    Decrypt {
        /// Input encrypted file
        #[arg(short, long)]
        input: PathBuf,

        /// Output decrypted file path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for decryption (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Validate device binding
        #[arg(long)]
        validate_device: bool,

        /// Path to public key for signature verification (optional)
        #[arg(short = 'k', long)]
        public_key: Option<PathBuf>,
    },

    /// Encrypt a directory (creates a tar archive, then encrypts)
    EncryptDir {
        /// Input directory to encrypt
        #[arg(short, long)]
        input: PathBuf,

        /// Output encrypted file path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for encryption (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Bind encryption to current device
        #[arg(long)]
        bind_device: bool,

        /// Path to private key for signing (optional)
        #[arg(short = 'k', long)]
        private_key: Option<PathBuf>,
    },

    /// Decrypt a directory archive
    DecryptDir {
        /// Input encrypted file
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory path
        #[arg(short, long)]
        output: PathBuf,

        /// Password for decryption (omit to enter interactively)
        #[arg(short, long)]
        password: Option<String>,

        /// Validate device binding
        #[arg(long)]
        validate_device: bool,

        /// Path to public key for signature verification (optional)
        #[arg(short = 'k', long)]
        public_key: Option<PathBuf>,
    },

    /// Generate Ed25519 key pair
    GenerateKeys {
        /// Output directory for keys
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,

        /// Name prefix for key files
        #[arg(short, long, default_value = "key")]
        name: String,
    },

    /// Sign a file with private key
    Sign {
        /// File to sign
        #[arg(short, long)]
        file: PathBuf,

        /// Private key path
        #[arg(short = 'k', long)]
        private_key: PathBuf,

        /// Output signature file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify file signature with public key
    Verify {
        /// File to verify
        #[arg(short, long)]
        file: PathBuf,

        /// Public key path
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Signature file
        #[arg(short, long)]
        signature: PathBuf,
    },

    /// Show device fingerprint
    Fingerprint,

    /// Validate device fingerprint
    ValidateFingerprint {
        /// Stored fingerprint to validate against
        fingerprint: String,
    },

    /// Generate default configuration file
    InitConfig {
        /// Output path (default: encryptor.toml)
        #[arg(short, long, default_value = "encryptor.toml")]
        output: PathBuf,
    },
}

/// Prompt for password interactively with confirmation for encryption.
fn prompt_password_encrypt() -> Result<String> {
    let password = rpassword::prompt_password("Enter encryption password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(password)
}

/// Prompt for password interactively (no confirmation, for decryption).
fn prompt_password_decrypt() -> Result<String> {
    let password = rpassword::prompt_password("Enter decryption password: ")?;
    Ok(password)
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

/// Archive a directory into a tar byte buffer.
fn archive_directory(dir_path: &PathBuf) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let mut archive = tar::Builder::new(buf);
    archive.append_dir_all(".", dir_path)?;
    let data = archive.into_inner()?;
    Ok(data)
}

/// Extract a tar archive from bytes into a directory.
fn extract_archive(data: &[u8], output_dir: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;
    let mut archive = tar::Archive::new(data);
    archive.unpack(output_dir)?;
    Ok(())
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let _config = Config::load_or_default();

    // Rate limiter: max 3 decryption attempts per 60-second window
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

            if bind_device {
                println!("Device binding enabled");
            }

            let keypair = if let Some(key_path) = private_key {
                Some(load_keypair(key_path)?)
            } else {
                None
            };

            if let Some(keypair) = keypair {
                EncryptedFile::encrypt_and_sign(
                    &input,
                    &output,
                    &password,
                    &keypair,
                    bind_device,
                )?;
                pb.finish_with_message("File encrypted and signed successfully!");
            } else {
                let device_id = if bind_device {
                    Some(get_device_fingerprint()?)
                } else {
                    None
                };

                encrypt_file(&input, &output, &password, device_id.as_deref())?;
                pb.finish_with_message("File encrypted successfully!");
            }
        }

        Commands::Decrypt { input, output, password, validate_device, public_key } => {
            validate_input_exists(&input)?;

            if let Err(_) = rate_limiter.check_rate_limit() {
                eprintln!("Rate limit exceeded. Too many decryption attempts. Please wait and try again.");
                std::process::exit(1);
            }

            let password = match password {
                Some(p) => p,
                None => prompt_password_decrypt()?,
            };

            let pb = create_spinner("Decrypting file...");

            let public_key_data = if let Some(key_path) = public_key {
                Some(load_public_key(key_path)?)
            } else {
                None
            };

            if let Some(public_key_data) = public_key_data {
                let metadata = EncryptedFile::decrypt_and_verify(
                    &input,
                    &output,
                    &password,
                    &public_key_data,
                    validate_device,
                )?;
                pb.finish_with_message("File decrypted and verified successfully!");
                println!("Original filename: {}", metadata.original_filename);
                println!("File size: {} bytes", metadata.file_size);
            } else {
                let device_id = if validate_device {
                    Some(get_device_fingerprint()?)
                } else {
                    None
                };

                decrypt_file(&input, &output, &password, device_id.as_deref())?;
                pb.finish_with_message("File decrypted successfully!");
            }
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

            // Archive the directory to a temp file
            let archive_data = archive_directory(&input)?;
            let temp_tar = tempfile::NamedTempFile::new()?;
            std::fs::write(temp_tar.path(), &archive_data)?;

            pb.set_message("Encrypting archive...".to_string());

            let device_id = if bind_device {
                Some(get_device_fingerprint()?)
            } else {
                None
            };

            if let Some(key_path) = private_key {
                let keypair = load_keypair(key_path)?;
                EncryptedFile::encrypt_and_sign(
                    temp_tar.path(),
                    &output,
                    &password,
                    &keypair,
                    bind_device,
                )?;
                pb.finish_with_message("Directory encrypted and signed successfully!");
            } else {
                encrypt_file(temp_tar.path(), &output, &password, device_id.as_deref())?;
                pb.finish_with_message("Directory encrypted successfully!");
            }
        }

        Commands::DecryptDir { input, output, password, validate_device, public_key } => {
            validate_input_exists(&input)?;

            if let Err(_) = rate_limiter.check_rate_limit() {
                eprintln!("Rate limit exceeded. Too many decryption attempts. Please wait and try again.");
                std::process::exit(1);
            }

            let password = match password {
                Some(p) => p,
                None => prompt_password_decrypt()?,
            };

            let pb = create_spinner("Decrypting archive...");

            let temp_tar = tempfile::NamedTempFile::new()?;

            let device_id = if validate_device {
                Some(get_device_fingerprint()?)
            } else {
                None
            };

            if let Some(key_path) = public_key {
                let public_key_data = load_public_key(key_path)?;
                EncryptedFile::decrypt_and_verify(
                    &input,
                    temp_tar.path(),
                    &password,
                    &public_key_data,
                    validate_device,
                )?;
            } else {
                decrypt_file(&input, temp_tar.path(), &password, device_id.as_deref())?;
            }

            pb.set_message("Extracting archive...".to_string());

            let tar_data = std::fs::read(temp_tar.path())?;
            extract_archive(&tar_data, &output)?;

            pb.finish_with_message("Directory decrypted and extracted successfully!");
        }

        Commands::GenerateKeys { output_dir, name } => {
            let pb = create_spinner("Generating Ed25519 key pair...");

            let keypair = generate_keypair()?;
            let private_key_path = output_dir.join(format!("{}_private.json", name));
            let public_key_path = output_dir.join(format!("{}_public.json", name));

            save_keypair(&keypair, &private_key_path)?;
            save_public_key(&keypair.public_key_only(), &public_key_path)?;

            pb.finish_with_message("Key pair generated successfully!");
            println!("Private key saved to: {:?}", private_key_path);
            println!("Public key saved to: {:?}", public_key_path);
        }

        Commands::Sign { file, private_key, output } => {
            validate_input_exists(&file)?;

            let pb = create_spinner("Signing file...");

            let keypair = load_keypair(private_key)?;
            let signature = sign_file(&file, &keypair)?;

            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("sig");
                path
            });

            std::fs::write(&output_path, &signature)?;
            pb.finish_with_message("File signed successfully!");
            println!("Signature saved to: {:?}", output_path);
        }

        Commands::Verify { file, public_key, signature } => {
            validate_input_exists(&file)?;

            let pb = create_spinner("Verifying file...");

            let public_key = load_public_key(public_key)?;
            let signature_bytes = std::fs::read(signature)?;
            let is_valid = verify_file(&file, &public_key, &signature_bytes)?;

            if is_valid {
                pb.finish_with_message("Signature verification successful!");
            } else {
                pb.finish_with_message("Signature verification FAILED!");
                std::process::exit(1);
            }
        }

        Commands::Fingerprint => {
            let fingerprint = get_device_fingerprint()?;
            println!("Device fingerprint: {}", fingerprint);
        }

        Commands::ValidateFingerprint { fingerprint } => {
            let is_valid = validate_device_fingerprint(&fingerprint)?;
            if is_valid {
                println!("Device fingerprint is valid!");
            } else {
                println!("Device fingerprint validation FAILED!");
                std::process::exit(1);
            }
        }

        Commands::InitConfig { output } => {
            Config::save_default(&output)?;
            println!("Default configuration saved to: {:?}", output);
        }
    }

    Ok(())
}
