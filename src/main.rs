#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};
use orion::kdf::{self, Password, Salt as OrionSalt};
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use zeroize::Zeroizing;

// --- CRYPTOGRAPHIC SPECIFICATIONS ---
const MAGIC: &[u8; 8] = b"FCRYPT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024; // 64KB block size

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

#[derive(Subcommand)]
enum Command {
    /// Encrypt a single file
    Encrypt { file: PathBuf },
    /// Decrypt a previously encrypted file
    Decrypt { file: PathBuf },
    /// Recursively encrypt a directory
    EncryptDir { dir: PathBuf },
    /// Recursively decrypt a directory
    DecryptDir { dir: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { file } => {
            let pw = prompt_password(true);
            encrypt_file(&file, &pw).unwrap_or_exit("Encryption failed");
        }
        Command::Decrypt { file } => {
            let pw = prompt_password(false);
            decrypt_file(&file, &pw).unwrap_or_exit("Decryption failed");
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password(true);
            walk_dir(&dir, &pw, true).unwrap_or_exit("Directory encryption failed");
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password(false);
            walk_dir(&dir, &pw, false).unwrap_or_exit("Directory decryption failed");
        }
    }
}

fn prompt_password(confirm: bool) -> Zeroizing<String> {
    print!("Password: ");
    io::stdout().flush().expect("Failed to flush stdout");
    let pw = read_password().expect("Failed to read password");

    if confirm {
        print!("Confirm password: ");
        io::stdout().flush().expect("Failed to flush stdout");
        let confirm_pw = read_password().expect("Failed to read password");
        if pw != confirm_pw {
            eprintln!("Error: Passwords do not match");
            exit(1);
        }
    }
    Zeroizing::new(pw)
}

/// Increment the nonce (Big-Endian) to ensure block uniqueness.
fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension().is_some_and(|e| e == "enc" || e == "tmp") {
        return Ok(());
    }

    let out_path = path.with_extension("enc");
    let mut tmp_path = out_path.clone();
    tmp_path.set_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    
    // rand 0.9 pattern
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base_nonce);

    let key = derive_key(password, &salt)?;
    let mut current_nonce_bytes = base_nonce;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    // Write file header
    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }

        let nonce = Nonce::from_slice(&current_nonce_bytes)
            .map_err(|_| io::Error::other("Nonce construction error"))?;
        
        let mut output_chunk = vec![0u8; n + TAG_LEN];
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], None, &mut output_chunk)
            .map_err(|_| io::Error::other("Cryptographic seal failure"))?;

        writer.write_all(&output_chunk)?;
        increment_nonce(&mut current_nonce_bytes);
    }

    writer.flush()?;
    drop(writer);
    fs::rename(&tmp_path, &out_path)?;
    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension() != Some("enc".as_ref()) {
        return Ok(());
    }

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid file format"));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    let key = derive_key(password, &salt)?;
    let mut current_nonce_bytes = base_nonce;

    let out_path = path.with_extension("");
    let mut tmp_path = out_path.clone();
    tmp_path.set_extension("tmp");

    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }

        if n < TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Truncated block"));
        }

        let nonce = Nonce::from_slice(&current_nonce_bytes)
            .map_err(|_| io::Error::other("Nonce construction error"))?;

        let mut plaintext = vec![0u8; n - TAG_LEN];
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], None, &mut plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Auth failure: invalid password or data tampered"))?;

        writer.write_all(&plaintext)?;
        increment_nonce(&mut current_nonce_bytes);
    }

    writer.flush()?;
    drop(writer);
    fs::rename(&tmp_path, &out_path)?;
    Ok(())
}

fn walk_dir(dir: &Path, pw: &Zeroizing<String>, encrypt: bool) -> io::Result<()> {
    if !dir.is_dir() { return Ok(()); }
    
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_dir(&path, pw, encrypt)?;
        } else if encrypt {
            encrypt_file(&path, pw)?;
        } else {
            decrypt_file(&path, pw)?;
        }
    }
    Ok(())
}

/// High-level Argon2id Key Derivation
fn derive_key(password: &Zeroizing<String>, salt: &[u8]) -> io::Result<OrionSecretKey> {
    let pw_wrapper = Password::from_slice(password.as_bytes())
        .map_err(|_| io::Error::other("Password init error"))?;
    let salt_wrapper = OrionSalt::from_slice(salt)
        .map_err(|_| io::Error::other("Salt init error"))?;
    
    // Using high-level KDF: Argon2id (3 passes, 64MB RAM, 1 parallelism)
    let derived_key = kdf::derive_key(&pw_wrapper, &salt_wrapper, 3, 64 * 1024, 1)
        .map_err(|_| io::Error::other("KDF derivation failed"))?;

    // Convert high-level key to hazardous AEAD key slice
    OrionSecretKey::from_slice(derived_key.unprotected_as_bytes())
        .map_err(|_| io::Error::other("Key cast failure"))
}

trait ExitOnErr<T> {
    fn unwrap_or_exit(self, msg: &str) -> T;
}

impl<T> ExitOnErr<T> for io::Result<T> {
    fn unwrap_or_exit(self, msg: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{msg}: {e}");
                exit(1);
            }
        }
    }
}
