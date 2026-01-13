#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use orion::{
    aead::{self, SecretKey},
    kdf,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use zeroize::{Zeroize, Zeroizing};

// --- CONSTANTS ---
// File Header: MAGIC (8) | SALT (16) | NONCE (24)
const MAGIC: &[u8; 8] = b"FCRYPT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

// Chunk Configuration
// Plaintext is read in 64KB chunks.
// Ciphertext is written as 64KB + 16 bytes (Poly1305 Tag).
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_LEN: usize = 16;

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
            encrypt_file(&file, &pw).unwrap_or_exit("encryption failed");
        }
        Command::Decrypt { file } => {
            let pw = prompt_password(false);
            decrypt_file(&file, &pw).unwrap_or_exit("decryption failed");
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password(true);
            walk_encrypt(&dir, &pw).unwrap_or_exit("directory encryption failed");
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password(false);
            walk_decrypt(&dir, &pw).unwrap_or_exit("directory decryption failed");
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
            eprintln!("Passwords do not match");
            exit(1);
        }
    }

    Zeroizing::new(pw)
}

/// Increments the nonce in Big-Endian order.
/// This ensures every chunk uses a unique nonce derived from the file's base nonce.
fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    // 1. Skip if already encrypted or is a temporary/system file
    if let Some(ext) = path.extension() {
        if ext == "enc" || ext == "tmp" {
            return Ok(());
        }
    }

    // 2. Prepare Output Paths
    let mut out_path = path.as_os_str().to_owned();
    out_path.push(".enc");
    let target_path = PathBuf::from(out_path);

    // Use a temp file for atomic writes
    let mut tmp_path = target_path.clone();
    tmp_path.set_extension("tmp");

    // 3. Generate Crypto Parameters
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    
    // We keep a running nonce for chunk encryption
    let mut current_nonce = nonce; 

    // 4. Open Files
    let input_file = File::open(path)?;
    let mut input = BufReader::new(input_file);
    
    let output_file = File::create(&tmp_path)?;
    let mut output = BufWriter::new(output_file);

    // 5. Write Header
    output.write_all(MAGIC)?;
    output.write_all(&salt)?;
    output.write_all(&nonce)?;

    // 6. Chunk Processing
    // Buffer is zeroized on drop automatically
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let chunk_nonce = aead::Nonce::from_slice(&current_nonce)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid nonce"))?;
        
        // Encrypt the chunk (Seal)
        // seal() produces [Ciphertext + Tag]
        let ciphertext = aead::seal(&key, &chunk_nonce, &buffer[..n])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption error"))?;

        output.write_all(&ciphertext)?;
        
        increment_nonce(&mut current_nonce);
    }

    output.flush()?;
    
    // 7. Atomic Rename (Finalize)
    fs::rename(&tmp_path, &target_path)?;

    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    // 1. Check extension
    if !path.extension().map_or(false, |e| e == "enc") {
        return Ok(());
    }

    // 2. Open Input
    let mut input_file = File::open(path)?;
    let mut input = BufReader::new(input_file);

    // 3. Read & Verify Header
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid file header"));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    input.read_exact(&mut salt)?;
    input.read_exact(&mut nonce)?;

    // 4. Derive Key
    let key = derive_key(password, &salt)?;
    let mut current_nonce = nonce;

    // 5. Prepare Output Paths (Atomic)
    let out_path = path.with_extension("");
    let mut tmp_path = out_path.clone();
    
    // Safely append .tmp to the original filename (e.g., file.txt -> file.txt.tmp)
    if let Some(ext) = tmp_path.extension() {
        let mut new_ext = ext.to_os_string();
        new_ext.push(".tmp");
        tmp_path.set_extension(new_ext);
    } else {
        tmp_path.set_extension("tmp");
    }

    let output_file = File::create(&tmp_path)?;
    let mut output = BufWriter::new(output_file);

    // 6. Chunk Processing
    // Buffer must be large enough to hold Ciphertext (max CHUNK_SIZE) + Tag (16 bytes)
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);

    loop {
        // We attempt to read a full chunk (ChunkSize + Tag). 
        // If we read less, it must be the EOF or a short last block.
        // We cannot use read_exact because the last chunk might be smaller.
        
        let mut chunk_buf = vec![0u8; CHUNK_SIZE + TAG_LEN];
        let mut bytes_read = 0;
        
        // Robust read loop to ensure we fill the buffer as much as the file allows
        while bytes_read < CHUNK_SIZE + TAG_LEN {
            let n = input.read(&mut chunk_buf[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            break; // EOF
        }

        // A valid encrypted chunk must have at least the Tag bytes
        if bytes_read < TAG_LEN {
             return Err(io::Error::new(io::ErrorKind::InvalidData, "Corrupted file: Chunk too short"));
        }

        let chunk_nonce = aead::Nonce::from_slice(&current_nonce)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid nonce"))?;

        // Decrypt (Open)
        // This function authenticates the data against the tag (last 16 bytes).
        // If the password is wrong or data corrupted, this returns Error.
        let plaintext = aead::open(&key, &chunk_nonce, &chunk_buf[..bytes_read])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption/Auth failed"))?;

        output.write_all(&plaintext)?;

        increment_nonce(&mut current_nonce);
    }

    output.flush()?;
    
    // 7. Finalize
    fs::rename(&tmp_path, &out_path)?;

    Ok(())
}

fn walk_encrypt(dir: &Path, pw: &Zeroizing<String>) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            // Skip symlinks to avoid loops or unintended encryption
            if path.is_symlink() {
                continue;
            }

            if path.is_dir() {
                walk_encrypt(&path, pw)?;
            } else {
                encrypt_file(&path, pw)?;
            }
        }
    }
    Ok(())
}

fn walk_decrypt(dir: &Path, pw: &Zeroizing<String>) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_symlink() {
                continue;
            }

            if path.is_dir() {
                walk_decrypt(&path, pw)?;
            } else {
                decrypt_file(&path, pw)?;
            }
        }
    }
    Ok(())
}

fn derive_key(password: &Zeroizing<String>, salt: &[u8]) -> io::Result<SecretKey> {
    let mut key_bytes = Zeroizing::new(vec![0u8; 32]);
    kdf::derive_key(
        &mut key_bytes,
        password.as_bytes(),
        salt,
        kdf::Params::argon2id(10, 64 * 1024, 1),
    )
    .map_err(|_| io::Error::new(io::ErrorKind::Other, "KDF failed"))?;

    SecretKey::from_slice(&key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Key init failed"))
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
