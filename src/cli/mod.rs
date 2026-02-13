use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

use crate::crypto::{encrypt_file, decrypt_file};
use crate::signature::{generate_keypair, save_keypair, load_keypair, save_public_key, load_public_key, sign_file, verify_file, KeyPair, PublicKeyOnly};
use crate::format::EncryptedFile;
use crate::hardware::{get_device_fingerprint, validate_device_fingerprint};

#[derive(Parser)]
#[command(name = "file-encryptor")]
#[command(about = "Universal file encryption system with advanced security features", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file with password and optional device binding
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output encrypted file path
        #[arg(short, long)]
        output: PathBuf,
        
        /// Password for encryption
        #[arg(short, long)]
        password: String,
        
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
        
        /// Password for decryption
        #[arg(short, long)]
        password: String,
        
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
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Encrypt { input, output, password, bind_device, private_key } => {
            println!("Encrypting file: {:?}", input);
            
            if bind_device {
                println!("Device binding enabled");
            }
            
            let keypair = if let Some(key_path) = private_key {
                println!("Loading private key for signing...");
                Some(load_keypair(key_path)?)
            } else {
                None
            };
            
            if let Some(keypair) = keypair {
                let device_id = if bind_device {
                    Some(get_device_fingerprint()?.as_str())
                } else {
                    None
                };
                
                EncryptedFile::encrypt_and_sign(
                    input,
                    output,
                    &password,
                    &keypair,
                    bind_device,
                )?;
                println!("File encrypted and signed successfully!");
            } else {
                // Fallback to basic encryption without signing
                let device_id = if bind_device {
                    Some(get_device_fingerprint()?.as_str())
                } else {
                    None
                };
                
                encrypt_file(input, output, &password, device_id)?;
                println!("File encrypted successfully!");
            }
        }
        
        Commands::Decrypt { input, output, password, validate_device, public_key } => {
            println!("Decrypting file: {:?}", input);
            
            if validate_device {
                println!("Device validation enabled");
            }
            
            let public_key = if let Some(key_path) = public_key {
                println!("Loading public key for signature verification...");
                Some(load_public_key(key_path)?)
            } else {
                None
            };
            
            if let Some(public_key) = public_key {
                let metadata = EncryptedFile::decrypt_and_verify(
                    input,
                    output,
                    &password,
                    &public_key,
                    validate_device,
                )?;
                println!("File decrypted and verified successfully!");
                println!("Original filename: {}", metadata.original_filename);
                println!("File size: {} bytes", metadata.file_size);
            } else {
                // Fallback to basic decryption without verification
                let device_id = if validate_device {
                    Some(get_device_fingerprint()?.as_str())
                } else {
                    None
                };
                
                decrypt_file(input, output, &password, device_id)?;
                println!("File decrypted successfully!");
            }
        }
        
        Commands::GenerateKeys { output_dir, name } => {
            println!("Generating Ed25519 key pair...");
            
            let keypair = generate_keypair()?;
            let private_key_path = output_dir.join(format!("{}_private.json", name));
            let public_key_path = output_dir.join(format!("{}_public.json", name));
            
            save_keypair(&keypair, &private_key_path)?;
            save_public_key(&keypair.public_key_only(), &public_key_path)?;
            
            println!("Key pair generated successfully!");
            println!("Private key saved to: {:?}", private_key_path);
            println!("Public key saved to: {:?}", public_key_path);
        }
        
        Commands::Sign { file, private_key, output } => {
            println!("Signing file: {:?}", file);
            
            let keypair = load_keypair(private_key)?;
            let signature = sign_file(&file, &keypair)?;
            
            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("sig");
                path
            });
            
            std::fs::write(&output_path, &signature)?;
            println!("File signed successfully!");
            println!("Signature saved to: {:?}", output_path);
        }
        
        Commands::Verify { file, public_key, signature } => {
            println!("Verifying file: {:?}", file);
            
            let public_key = load_public_key(public_key)?;
            let signature_bytes = std::fs::read(signature)?;
            let is_valid = verify_file(&file, &public_key, &signature_bytes)?;
            
            if is_valid {
                println!("✅ Signature verification successful!");
            } else {
                println!("❌ Signature verification failed!");
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
                println!("✅ Device fingerprint is valid!");
            } else {
                println!("❌ Device fingerprint validation failed!");
                std::process::exit(1);
            }
        }
    }
    
    Ok(())
}