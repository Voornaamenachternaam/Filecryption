use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use rand::RngCore;
use rpassword::prompt_password;
use zeroize::Zeroizing;
use argon2::{Argon2, Algorithm, Version, Params};
use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

/// The magic header identifying an encrypted file.
const MAGIC: &[u8; 8] = b"FCRYPT01";
/// Length of the random salt used in key derivation.
const SALT_LEN: usize = 16;
/// Length of the XChaCha20 nonce.
const NONCE_LEN: usize = 24;
/// Length of the Poly1305 authentication tag.
const TAG_LEN: usize = 16;
/// Size of the I/O buffer for streaming file operations.
const CHUNK_SIZE: usize = 64 * 1024;
/// Argon2id memory cost parameter (in KiB).
const MEMORY_COST: u32 = 1 << 20; // 2^20 KiB = 1 GiB
/// Argon2id time cost parameter.
const TIME_COST: u32 = 10;
/// Argon2id parallelism parameter.
const PARALLELISM: u32 = 1;

/// RAII guard for a temporary file, ensuring its removal on drop unless persisted.
struct TempFile {
    path: PathBuf,
    active: bool,
}

impl TempFile {
    /// Creates a new empty file at the given path.
    fn create(path: &Path) -> io::Result<Self> {
        let _ = File::create(path)?;
        Ok(TempFile {
            path: path.to_path_buf(),
            active: true,
        })
    }

    /// Marks the temporary file as persisted, preventing its deletion on drop.
    fn persist(mut self) {
        self.active = false;
    }
}

impl Drop for TempFile {
    /// Deletes the tracked file if it is still marked as active.
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Command Line Interface definition using Clap.
#[derive(Parser)]
#[command(
    name = "filecryption",
    version,
    about = "Secure file encryption using Argon2id + XChaCha20-Poly1305",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Enumeration of supported commands.
#[derive(Subcommand)]
enum Command {
    /// Encrypt a single file.
    Encrypt { file: PathBuf },
    /// Decrypt a single file.
    Decrypt { file: PathBuf },
    /// Recursively encrypt all files in a directory.
    EncryptDir { dir: PathBuf },
    /// Recursively decrypt all files in a directory.
    DecryptDir { dir: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { file } => {
            let pw = prompt_password_secure(true).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {}", e);
                exit(1);
            });
            if let Err(e) = encrypt_file(&file, &pw) {
                eprintln!("Encryption of '{}' failed: {}", file.display(), e);
                exit(1);
            }
        }
        Command::Decrypt { file } => {
            let pw = prompt_password_secure(false).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {}", e);
                exit(1);
            });
            if let Err(e) = decrypt_file(&file, &pw) {
                eprintln!("Decryption of '{}' failed: {}", file.display(), e);
                exit(1);
            }
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password_secure(true).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {}", e);
                exit(1);
            });
            if let Err(e) = walk_dir(&dir, &pw, true) {
                eprintln!("Directory encryption of '{}' failed: {}", dir.display(), e);
                exit(1);
            }
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password_secure(false).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {}", e);
                exit(1);
            });
            if let Err(e) = walk_dir(&dir, &pw, false) {
                eprintln!("Directory decryption of '{}' failed: {}", dir.display(), e);
                exit(1);
            }
        }
    }
}

/// Prompts the user for a master password, enforcing length and confirmation.
fn prompt_password_secure(confirm: bool) -> io::Result<Zeroizing<String>> {
    let pw = prompt_password("Enter Master Password: ")?;
    if pw.len() < 12 {
        eprintln!("Security Error: Password must be at least 12 characters.");
        exit(1);
    }
    if confirm {
        let confirm_pw = prompt_password("Confirm Master Password: ")?;
        if pw != confirm_pw {
            eprintln!("Security Error: Passwords do not match.");
            exit(1);
        }
    }
    Ok(Zeroizing::new(pw))
}

/// Encrypts a single file using XChaCha20-Poly1305 and Argon2id.
fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    let out_path = path.with_extension("enc");
    // Do not overwrite an existing encrypted file.
    if out_path.exists() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Output file already exists.",
        ));
    }
    let tmp_path = out_path.with_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut base_nonce);

    let key = derive_key(password, &salt)?;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let tmp_file_handler = TempFile::create(&tmp_path)?;
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    // Write the file header.
    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    // Use a pre-allocated buffer for efficiency.
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut cur_nonce = base_nonce;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::other("Invalid nonce state"))?;
        
        let mut ciphertext_chunk = Vec::with_capacity(n + TAG_LEN);
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], None, &mut ciphertext_chunk)
            .map_err(|_| io::Error::other("AEAD seal operation failed"))?;

        writer.write_all(&ciphertext_chunk)?;
        
        // Advance the nonce for the next chunk.
        for i in (0..NONCE_LEN).rev() {
            cur_nonce[i] = cur_nonce[i].wrapping_add(1);
            if cur_nonce[i] != 0 {
                break;
            }
        }
    }

    writer.flush()?;
    drop(writer); // Flush writer and close file handle.

    fs::rename(&tmp_path, &out_path)?;
    tmp_file_handler.persist(); // Prevent cleanup on success.
    Ok(())
}

/// Decrypts a single file previously encrypted with XChaCha20-Poly1305 and Argon2id.
fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension().and_then(|s| s.to_str()) != Some("enc") {
        // Not an encrypted file, do nothing to avoid errors.
        return Ok(());
    }

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Invalid file format: MAGIC header mismatch",
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    let key = derive_key(password, &salt)?;
    let mut cur_nonce = base_nonce;

    let out_path = path.with_extension("");
    let tmp_path = out_path.with_extension("tmp");
    let tmp_file_handler = TempFile::create(&tmp_path)?;
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        
        // Ensure there is enough data for a tag.
        if n < TAG_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Ciphertext is too short for a valid tag.",
            ));
        }

        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::other("Invalid nonce state"))?;
        
        let mut plaintext_chunk = Vec::with_capacity(n - TAG_LEN);
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], None, &mut plaintext_chunk)
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "Authentication failed: incorrect password or corrupted data.",
                )
            })?;

        writer.write_all(&plaintext_chunk)?;
        
        // Advance the nonce for the next chunk.
        for i in (0..NONCE_LEN).rev() {
            cur_nonce[i] = cur_nonce[i].wrapping_add(1);
            if cur_nonce[i] != 0 {
                break;
            }
        }
    }

    writer.flush()?;
    drop(writer);

    fs::rename(&tmp_path, &out_path)?;
    tmp_file_handler.persist();
    Ok(())
}

/// Recursively processes all files within a directory.
fn walk_dir(dir: &Path, pw: &Zeroizing<String>, encrypt: bool) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_dir(&path, pw, encrypt)?; // Propagate errors upwards.
        } else if encrypt {
            encrypt_file(&path, pw)?;
        } else {
            decrypt_file(&path, pw)?;
        }
    }
    Ok(())
}

/// Derives a 256-bit secret key from a password and salt using Argon2id.
fn derive_key(password: &Zeroizing<String>, salt: &[u8; SALT_LEN]) -> io::Result<OrionSecretKey> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(32))
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Argon2 parameter validation failed: {}", e)))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = [0u8; 32];

    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut raw_key,
    ).map_err(|e| io::Error::other(format!("Argon2 key derivation failed: {}", e)))?;

    OrionSecretKey::from_slice(&raw_key)
        .map_err(|_| io::Error::other("Failed to initialize Orion secret key"))
}
