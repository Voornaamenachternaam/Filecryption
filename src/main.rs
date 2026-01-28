use std::fs::{self, File};
use std::io::{Read, BufReader, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use rand::Rng;
use rpassword::prompt_password;
use zeroize::Zeroizing;
use argon2::{Argon2, Algorithm, Version, Params};

use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

const MAGIC: &[u8; 8] = b"FCRYPT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const MEMORY_COST: u32 = 1 << 20; // 2^20 KiB = 1 GiB
const TIME_COST: u32 = 10;
const PARALLELISM: u32 = 1;

/// RAII handle for temporary files that ensures cleanup on failure but allows persistence on success.
struct TempFile {
    path: PathBuf,
    active: bool,
}

impl TempFile {
    fn create(path: &Path) -> io::Result<Self> {
        File::create(path)?;
        Ok(TempFile {
            path: path.to_path_buf(),
            active: true,
        })
    }

    fn persist(mut self) {
        self.active = false;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

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
            let pw = prompt_password_secure(true).unwrap_or_exit("Password prompt failed");
            encrypt_file(&file, &pw).unwrap_or_exit("Encryption process terminated");
        }
        Command::Decrypt { file } => {
            let pw = prompt_password_secure(false).unwrap_or_exit("Password prompt failed");
            decrypt_file(&file, &pw).unwrap_or_exit("Decryption process terminated");
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password_secure(true).unwrap_or_exit("Password prompt failed");
            walk_dir(&dir, &pw, true).unwrap_or_exit("Directory encryption terminated");
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password_secure(false).unwrap_or_exit("Password prompt failed");
            walk_dir(&dir, &pw, false).unwrap_or_exit("Directory decryption terminated");
        }
    }
}

fn prompt_password_secure(confirm: bool) -> io::Result<Zeroizing<String>> {
    let pw = prompt_password("Enter Master Password: ")?;
    if pw.len() < 12 {
        eprintln!("Security Error: Password must be at least 12 characters.");
        exit(1);
    }
    if confirm {
        let confirm_pw = prompt_password("Confirm Master Password: ")?;
        if pw!= confirm_pw {
            eprintln!("Security Error: Passwords do not match.");
            exit(1);
        }
    }
    Ok(Zeroizing::new(pw))
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (val, overflow) = byte.overflowing_add(1);
        *byte = val;
        if!overflow {
            break;
        }
    }
}

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if let Some(ext) = path.extension() {
        if ext == "enc" || ext == "tmp" {

| ext == "tmp" {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "File already possesses an.enc or.tmp extension",
            ));
        }
    }

    let out_path = path.with_extension("enc");
    let tmp_path = out_path.with_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut base_nonce);

    let key = derive_key(password, &salt)?;
    let mut cur_nonce = base_nonce;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let tmp_file_handler = TempFile::create(&tmp_path)?;
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    let mut buffer = vec!;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let nonce = Nonce::from_slice(&cur_nonce)
           .map_err(|_| io::Error::new(ErrorKind::Other, "Orion nonce state corruption"))?;
        
        let mut out_chunk = vec!;
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], None, &mut out_chunk)
           .map_err(|_| io::Error::new(ErrorKind::Other, "AEAD seal failure: buffer overflow or logic error"))?;
        
        writer.write_all(&out_chunk)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);
    
    fs::rename(&tmp_path, &out_path)?;
    tmp_file_handler.persist();

    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension().and_then(|s| s.to_str())!= Some("enc") {
        return Ok(());
    }

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic!= MAGIC {
        return Err(io::Error::new(ErrorKind::InvalidData, "Invalid file format: MAGIC header mismatch"));
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

    let mut buffer = vec!;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n < TAG_LEN {
            return Err(io::Error::new(ErrorKind::InvalidData, "Ciphertext integrity error: truncated chunk"));
        }

        let nonce = Nonce::from_slice(&cur_nonce)
           .map_err(|_| io::Error::new(ErrorKind::Other, "Orion nonce state corruption"))?;
        
        let mut plaintext = vec!;
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], None, &mut plaintext)
           .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Authentication failure: data tampered or incorrect password"))?;
        
        writer.write_all(&plaintext)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);

    fs::rename(&tmp_path, &out_path)?;
    tmp_file_handler.persist();

    Ok(())
}

fn walk_dir(dir: &Path, pw: &Zeroizing<String>, encrypt: bool) -> io::Result<()> {
    if!dir.is_dir() {
        return Ok(());
    }
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

fn derive_key(password: &Zeroizing<String>, salt: &[u8]) -> io::Result<OrionSecretKey> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(32))
       .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Argon2 configuration error: {e}")))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = Zeroizing::new([0u8; 32]);
    
    argon2.hash_password_into(password.as_bytes(), salt, raw_key.as_mut())
       .map_err(|e| io::Error::new(ErrorKind::Other, format!("Argon2 computation failure: {e}")))?;
    
    OrionSecretKey::from_slice(raw_key.as_ref())
       .map_err(|_| io::Error::new(ErrorKind::Other, "Orion key initialization failed"))
}

trait ExitOnErr<T> {
    fn unwrap_or_exit(self, msg: &str) -> T;
}

impl<T> ExitOnErr<T> for io::Result<T> {
    fn unwrap_or_exit(self, msg: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Critical Fault: {msg} - {e}");
                exit(1);
            }
        }
    }
} 
