use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use rand::rngs::StdRng;
use rand::{SeedableRng, TryRngCore};
use rpassword::read_password;
use zeroize::Zeroizing;
use argon2::{argon2i, Config};

use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

const MAGIC: &[u8; 8] = b"FCRYPT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const MEMORY_COST: u32 = 1 << 20;
const TIME_COST: u32 = 10;
const PARALLELISM: u32 = 1;

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
    Encrypt { file: PathBuf },
    Decrypt { file: PathBuf },
    EncryptDir { dir: PathBuf },
    DecryptDir { dir: PathBuf },
}

struct TempFile {
    file: File,
    path: PathBuf,
}
impl TempFile {
    fn create(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(TempFile {
            file,
            path: path.to_path_buf(),
        })
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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
    if pw.as_bytes().len() < 12 {
        eprintln!("Error: Password must be at least 12 characters");
        exit(1);
    }
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

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if let Some(ext) = path.extension() {
        if ext == "enc" || ext == "tmp" {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "File already has .enc or .tmp extension",
            ));
        }
    }

    let metadata = fs::metadata(path)?;
    let max_len = (1u64 << 24) * CHUNK_SIZE as u64;
    if metadata.len() > max_len {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "File too large for a single nonce stream",
        ));
    }

    let out_path = path.with_extension("enc");
    let mut tmp_path = out_path.clone();
    tmp_path.set_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().try_fill_bytes(&mut salt)?;
    rand::thread_rng().try_fill_bytes(&mut base_nonce)?;

    let key = derive_key(password, &salt)?;
    let mut cur_nonce = base_nonce;

    let mut tmp_file = TempFile::create(&tmp_path)?;
    let mut writer = BufWriter::new(&mut tmp_file.file);

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Nonce construction error"))?;
        let mut out_chunk = vec![0u8; n + TAG_LEN];
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], None, &mut out_chunk)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Seal failure"))?;
        writer.write_all(&out_chunk)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);
    drop(tmp_file); // ensure .tmp is removed even on early return

    fs::rename(&tmp_path, &out_path)?;
    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if let Some(ext) = path.extension() {
        if ext != "enc" {
            return Ok(());
        }
    }

    let mut input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(ErrorKind::InvalidData, "Invalid file format"));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    let key = derive_key(password, &salt)?;
    let mut cur_nonce = base_nonce;

    let out_path = path.with_extension("");
    let mut tmp_path = out_path.clone();
    tmp_path.set_extension("tmp");

    let mut tmp_file = TempFile::create(&tmp_path)?;
    let mut writer = BufWriter::new(&mut tmp_file.file);

    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n < TAG_LEN {
            return Err(io::Error::new(ErrorKind::InvalidData, "Truncated block"));
        }
        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Nonce construction error"))?;
        let mut plaintext = vec![0u8; n - TAG_LEN];
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], None, &mut plaintext)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Auth failure"))?;
        writer.write_all(&plaintext)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);
    drop(tmp_file); // remove .tmp file

    fs::rename(&tmp_path, &out_path)?;
    Ok(())
}

fn walk_dir(dir: &Path, pw: &Zeroizing<String>, encrypt: bool) -> io::Result<()> {
    if !dir.is_dir() {
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
    let mut cfg = Config::new()
        .mem_cost(MEMORY_COST)
        .time_cost(TIME_COST)
        .parallelism(PARALLELISM)
        .add_flag(argon2::Flags::RECOMMENDATIONS);
    let argon2 = argon2i::Argon2::with_config(&cfg);
    let raw_key = argon2
        .hash_raw(password.as_bytes(), salt)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("Argon2 error: {e}")))?;
    let secret_key = OrionSecretKey::from_slice(&raw_key)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Key cast failure"))?;
    for b in raw_key.iter_mut() {
        *b = 0;
    }
    Ok(secret_key)
}

trait ExitOnErr<T> {
    fn unwrap_or_exit(self, msg: &str) -> T;
}
impl<T> ExitOnErr<T> for io::Result<T> {
    fn unwrap_or_exit(self, msg: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{msg}: {e} ({:?})", e.kind());
                exit(1);
            }
        }
    }
}
