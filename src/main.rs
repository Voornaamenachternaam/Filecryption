use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use rand::thread_rng;
use rpassword::read_password;
use tempfile::Builder as TempFileBuilder;
use zeroize::{Zeroize, Zeroizing};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};

use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

const MAGIC: &[u8; 8] = b"FCRYPT02";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
const DEFAULT_MEMORY_COST: u32 = 262144; // 256 MiB
const DEFAULT_TIME_COST: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const MAX_RECURSION_DEPTH: usize = 256;
const MAX_FILE_SIZE: u128 = (1 << 24) as u128 * CHUNK_SIZE as u128; // 16 TiB

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
    command: Commands,
    #[arg(long, global = true, default_value_t = DEFAULT_MEMORY_COST)]
    memory_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_TIME_COST)]
    time_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_PARALLELISM)]
    parallelism: u32,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        file: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    Decrypt {
        file: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    EncryptDir {
        dir: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    DecryptDir {
        dir: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    if cli.memory_cost < 4096 {
        eprintln!("Error: Memory cost must be at least 4096 KiB");
        exit(1);
    }
    if cli.time_cost < 1 {
        eprintln!("Error: Time cost must be at least 1");
        exit(1);
    }
    if cli.parallelism < 1 {
        eprintln!("Error: Parallelism must be at least 1");
        exit(1);
    }

    match &cli.command {
        Commands::Encrypt { file, force } => {
            let pw = prompt_password(true);
            encrypt_file(file, &pw, *force, &cli).unwrap_or_exit("Encryption failed");
        }
        Commands::Decrypt { file, force } => {
            let pw = prompt_password(false);
            decrypt_file(file, &pw, *force).unwrap_or_exit("Decryption failed");
        }
        Commands::EncryptDir { dir, force } => {
            let pw = prompt_password(true);
            walk_dir(dir, &pw, true, *force, &cli, 0).unwrap_or_exit("Directory encryption failed");
        }
        Commands::DecryptDir { dir, force } => {
            let pw = prompt_password(false);
            walk_dir(dir, &pw, false, *force, &cli, 0).unwrap_or_exit("Directory decryption failed");
        }
    }
}

fn prompt_password(confirm: bool) -> Zeroizing<String> {
    print!("Password: ");
    io::stdout().flush().expect("Failed to flush stdout");
    let pw = read_password().expect("Failed to read password").into();
    if pw.as_bytes().len() < 16 {
        eprintln!("Error: Password must be at least 16 characters");
        exit(1);
    }
    if confirm {
        print!("Confirm password: ");
        io::stdout().flush().expect("Failed to flush stdout");
        let confirm_pw = read_password().expect("Failed to read password").into();
        if pw != confirm_pw {
            eprintln!("Error: Passwords do not match");
            exit(1);
        }
    }
    pw
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn get_aad(path: &Path) -> Vec<u8> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(Vec::new)
}

fn encrypt_file(
    path: &Path,
    password: &Zeroizing<String>,
    force: bool,
    cli: &Cli,
) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Input path is a directory"));
    }
    if !path.exists() {
        return Err(io::Error::new(ErrorKind::NotFound, "Input file not found"));
    }

    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE as u64 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("File exceeds maximum size of {} TiB", MAX_FILE_SIZE >> 40),
        ));
    }

    let out_path = path.with_extension(format!("{}.enc", path.extension().unwrap_or_default().to_string_lossy()));
    if out_path.exists() && !force {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "Output file exists (use --force to overwrite)",
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    thread_rng().fill_bytes(&mut salt);
    thread_rng().fill_bytes(&mut base_nonce);

    let key = derive_key(
        password,
        &salt,
        cli.memory_cost,
        cli.time_cost,
        cli.parallelism,
    )?;
    let mut cur_nonce = base_nonce;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let tmp_file = TempFileBuilder::new()
        .prefix(&out_path.file_name().unwrap_or_else(|| "filecryption".as_ref()).to_string_lossy())
        .suffix(".tmp")
        .tempfile_in(out_path.parent().unwrap_or_else(|| Path::new(".")))?;
    let tmp_path = tmp_file.path().to_path_buf();
    let mut writer = BufWriter::new(tmp_file.reopen()?);

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    let aad = get_aad(path);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid nonce"))?;
        let mut out_chunk = vec![0u8; n + TAG_LEN];
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], Some(&aad), &mut out_chunk)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Encryption failed"))?;
        writer.write_all(&out_chunk)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);
    tmp_file.persist(&out_path).map_err(|e| e.error)?;
    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>, force: bool) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Input path is a directory"));
    }
    if !path.exists() {
        return Err(io::Error::new(ErrorKind::NotFound, "Input file not found"));
    }

    let mut input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Invalid magic number (file not encrypted by this tool)",
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    let key = derive_key(
        password,
        &salt,
        DEFAULT_MEMORY_COST,
        DEFAULT_TIME_COST,
        DEFAULT_PARALLELISM,
    )?;
    let mut cur_nonce = base_nonce;

    let stem = path.file_stem().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "Input file has no stem (cannot determine output name)")
    })?;
    let out_path = path.with_file_name(stem);
    if out_path.exists() && !force {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "Output file exists (use --force to overwrite)",
        ));
    }

    let tmp_file = TempFileBuilder::new()
        .prefix(&out_path.file_name().unwrap_or_else(|| "filecryption".as_ref()).to_string_lossy())
        .suffix(".tmp")
        .tempfile_in(out_path.parent().unwrap_or_else(|| Path::new(".")))?;
    let tmp_path = tmp_file.path().to_path_buf();
    let mut writer = BufWriter::new(tmp_file.reopen()?);

    let aad = get_aad(&out_path);
    let mut buffer = vec![0u8; CHUNK_SIZE + TAG_LEN];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n < TAG_LEN {
            return Err(io::Error::new(ErrorKind::InvalidData, "Truncated ciphertext block"));
        }
        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid nonce"))?;
        let mut plaintext = vec![0u8; n - TAG_LEN];
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], Some(&aad), &mut plaintext)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Authentication failed (corrupted or tampered data)"))?;
        writer.write_all(&plaintext)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);
    tmp_file.persist(&out_path).map_err(|e| e.error)?;
    Ok(())
}

fn walk_dir(
    dir: &Path,
    pw: &Zeroizing<String>,
    encrypt: bool,
    force: bool,
    cli: &Cli,
    depth: usize,
) -> io::Result<()> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(io::Error::new(ErrorKind::Other, "Maximum directory depth exceeded"));
    }

    if !dir.is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Path is not a directory"));
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_symlink() {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            walk_dir(&path, pw, encrypt, force, cli, depth + 1)?;
        } else if metadata.is_file() {
            if encrypt {
                encrypt_file(&path, pw, force, cli)?;
            } else if path.extension().map_or(false, |ext| ext == "enc") {
                decrypt_file(&path, pw, force)?;
            }
        }
    }
    Ok(())
}

fn derive_key(
    password: &Zeroizing<String>,
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> io::Result<OrionSecretKey> {
    let params = ParamsBuilder::new()
        .m_cost(memory_cost)
        .t_cost(time_cost)
        .p_cost(parallelism)
        .key_length(32)
        .hash_length(32)
        .version(Version::V0x13)
        .algorithm(Algorithm::Argon2id)
        .build()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("Argon2 parameter error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut raw_key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("Key derivation failed: {}", e)))?;

    let secret_key = OrionSecretKey::from_slice(&raw_key).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "Failed to convert raw key to secret key",
        )
    })?;

    raw_key.zeroize();
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
                eprintln!("{}: {} ({:?})", msg, e, e.kind());
                exit(1);
            }
        }
    }
}
