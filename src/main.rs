use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use zeroize::{Zeroize, Zeroizing};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

const MAGIC: &[u8; 8] = b"FCRYPT03";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
const DEFAULT_MEMORY_COST: u32 = 262144; // 256 MiB
const DEFAULT_TIME_COST: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const MAX_RECURSION_DEPTH: usize = 1024;
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024; // 16 TiB
const MAX_MEMORY_COST: u32 = 4 * 1024 * 1024; // 4 GiB
const MIN_PASSWORD_LENGTH: usize = 16;

struct TempFile {
    path: PathBuf,
    file: File,
    persisted: bool,
}

impl TempFile {
    fn new_in(dir: &Path, prefix: &str, suffix: &str) -> io::Result<Self> {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes);
        let random_str = format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3],
            random_bytes[4], random_bytes[5], random_bytes[6], random_bytes[7]
        );

        let file_name = format!("{}.{}.{}", prefix, random_str, suffix);
        let path = dir.join(file_name);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;

        Ok(TempFile {
            path,
            file,
            persisted: false,
        })
    }

    fn reopen(&self) -> io::Result<File> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.path)
    }

    fn persist(mut self, new_path: &Path) -> io::Result<()> {
        if self.persisted {
            return Err(io::Error::new(ErrorKind::Other, "TempFile already persisted"));
        }
        self.file.flush()?;
        self.file.sync_all()?;
        drop(self.file);
        fs::rename(&self.path, new_path)?;
        self.persisted = true;
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = self.file.flush();
            let _ = self.file.sync_all();
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
    arg_required_else_help = true,
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, global = true, default_value_t = DEFAULT_MEMORY_COST, value_name = "KILOBYTES")]
    memory_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_TIME_COST)]
    time_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_PARALLELISM)]
    parallelism: u32,
    #[arg(short = 'V', long, help = "Print version information")]
    version: bool,
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
        #[arg(short, long
```rust
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::read_password;
use zeroize::{Zeroize, Zeroizing};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};

const MAGIC: &[u8; 8] = b"FCRYPT03";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
const DEFAULT_MEMORY_COST: u32 = 262144; // 256 MiB
const DEFAULT_TIME_COST: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;
const MAX_RECURSION_DEPTH: usize = 1024;
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024; // 16 TiB
const MAX_MEMORY_COST: u32 = 4 * 1024 * 1024; // 4 GiB
const MIN_PASSWORD_LENGTH: usize = 16;

struct TempFile {
    path: PathBuf,
    file: File,
    persisted: bool,
}

impl TempFile {
    fn new_in(dir: &Path, prefix: &str, suffix: &str) -> io::Result<Self> {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes);
        let random_str = format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3],
            random_bytes[4], random_bytes[5], random_bytes[6], random_bytes[7]
        );

        let file_name = format!("{}.{}.{}", prefix, random_str, suffix);
        let path = dir.join(file_name);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;

        Ok(TempFile {
            path,
            file,
            persisted: false,
        })
    }

    fn reopen(&self) -> io::Result<File> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.path)
    }

    fn persist(mut self, new_path: &Path) -> io::Result<()> {
        if self.persisted {
            return Err(io::Error::new(ErrorKind::Other, "TempFile already persisted"));
        }
        self.file.flush()?;
        self.file.sync_all()?;
        drop(self.file);
        fs::rename(&self.path, new_path)?;
        self.persisted = true;
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = self.file.flush();
            let _ = self.file.sync_all();
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
    arg_required_else_help = true,
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, global = true, default_value_t = DEFAULT_MEMORY_COST, value_name = "KILOBYTES")]
    memory_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_TIME_COST)]
    time_cost: u32,
    #[arg(long, global = true, default_value_t = DEFAULT_PARALLELISM)]
    parallelism: u32,
    #[arg(short = 'V', long, help = "Print version information")]
    version: bool,
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

    if cli.version {
        println!("filecryption {}", env!("CARGO_PKG_VERSION"));
        exit(0);
    }

    validate_parameters(&cli).unwrap_or_exit("Invalid parameters");

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

fn validate_parameters(cli: &Cli) -> io::Result<()> {
    if cli.memory_cost < 4096 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Memory cost must be at least 4096 KiB (4 MiB)",
        ));
    }
    if cli.memory_cost > MAX_MEMORY_COST {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Memory cost must not exceed {} KiB (4 GiB)", MAX_MEMORY_COST),
        ));
    }
    if cli.time_cost < 1 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Time cost must be at least 1"));
    }
    if cli.time_cost > 10 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Time cost must not exceed 10"));
    }
    if cli.parallelism < 1 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Parallelism must be at least 1"));
    }
    if cli.parallelism > 16 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Parallelism must not exceed 16"));
    }
    Ok(())
}

fn prompt_password(confirm: bool) -> Zeroizing<String> {
    print!("Password: ");
    io::stdout().flush().expect("Failed to flush stdout");
    let pw = Zeroizing::new(read_password().expect("Failed to read password"));
    if pw.as_bytes().len() < MIN_PASSWORD_LENGTH {
        eprintln!(
            "Error: Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        );
        exit(1);
    }
    if confirm {
        print!("Confirm password: ");
        io::stdout().flush().expect("Failed to flush stdout");
        let confirm_pw = Zeroizing::new(read_password().expect("Failed to read password"));
        if !constant_time_eq(pw.as_bytes(), confirm_pw.as_bytes()) {
            eprintln!("Error: Passwords do not match");
            exit(1);
        }
    }
    pw
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
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
    let mut aad = Vec::new();
    if let Some(name) = path.file_name() {
        aad.extend_from_slice(name.as_encoded_bytes());
    }
    if let Ok(metadata) = fs::metadata(path) {
        aad.extend_from_slice(&metadata.len().to_le_bytes());
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                aad.extend_from_slice(&duration.as_secs().to_le_bytes());
                aad.extend_from_slice(&duration.subsec_nanos().to_le_bytes());
            }
        }
    }
    aad
}

fn is_regular_file(metadata: &Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink()
}

fn encrypt_file(
    path: &Path,
    password: &Zeroizing<String>,
    force: bool,
    cli: &Cli,
) -> io::Result<()> {
    let metadata = fs::metadata(path).map_err(|e| {
        io::Error::new(
            match e.kind() {
                ErrorKind::NotFound => ErrorKind::NotFound,
                _ => ErrorKind::InvalidInput,
            },
            format!("Failed to access input file: {}", e),
        )
    })?;

    if !is_regular_file(&metadata) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Input must be a regular file (not a directory, symlink, or special file)",
        ));
    }

    if metadata.len() > MAX_FILE_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "File exceeds maximum size of {} TiB",
                MAX_FILE_SIZE as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
            ),
        ));
    }

    let out_path = path.with_file_name(format!(
        "{}.enc",
        path.file_name()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Invalid file name"))?
            .to_string_lossy()
    ));

    if out_path.exists() && !force {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "Output file exists: {} (use --force to overwrite)",
                out_path.display()
            ),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut base_nonce);

    let key = derive_key(
        password,
        &salt,
        cli.memory_cost,
        cli.time_cost,
        cli.parallelism,
    )?;
    let mut cur_nonce = base_nonce;

    let input = File::open(path)?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, input);

    let parent_dir = out_path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_file = TempFile::new_in(
        parent_dir,
        &out_path
            .file_name()
            .unwrap_or_else(|| "filecryption".as_ref())
            .to_string_lossy(),
        "tmp",
    )
    .map_err(|e| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Failed to create temp file in {}: {}", parent_dir.display(), e),
        )
    })?;
    let tmp_path = tmp_file.path().to_path_buf();
    let mut writer = BufWriter::with_capacity(CHUNK_SIZE, tmp_file.reopen()?);

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;

    let aad = get_aad(path);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        if total_bytes > MAX_FILE_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "File exceeds maximum size of {} TiB during processing",
                    MAX_FILE_SIZE as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
                ),
            ));
        }

        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid nonce structure"))?;
        let mut out_chunk = vec![0u8; n + TAG_LEN];
        xchacha20poly1305::seal(&key, &nonce, &buffer[..n], Some(&aad), &mut out_chunk)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Encryption failed - possible hardware error"))?;
        writer.write_all(&out_chunk)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io::Error::new(ErrorKind::PermissionDenied, format!("Failed to set secure permissions: {}", e)))?;
    }

    if force && out_path.exists() {
        fs::remove_file(&out_path).map_err(|e| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                format!("Failed to remove existing file: {}", e),
            )
        })?;
    }

    tmp_file
        .persist(&out_path)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("File persistence failed: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&out_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io::Error::new(ErrorKind::PermissionDenied, format!("Failed to set secure permissions: {}", e)))?;
    }

    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>, force: bool) -> io::Result<()> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "Input file has no valid file name")
    })?;

    let file_name_str = file_name.to_string_lossy();
    if !file_name_str.ends_with(".enc") {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "File does not have .enc extension - skipping decryption",
        ));
    }

    if file_name_str.len() <= 4 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "File name would be empty after removing .enc extension",
        ));
    }

    let out_path = path.with_file_name(&file_name_str[..file_name_str.len() - 4]);

    if out_path.exists() && !force {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "Output file exists: {} (use --force to overwrite)",
                out_path.display()
            ),
        ));
    }

    let mut input = File::open(path).map_err(|e| {
        io::Error::new(
            match e.kind() {
                ErrorKind::NotFound => ErrorKind::NotFound,
                _ => ErrorKind::InvalidInput,
            },
            format!("Failed to open encrypted file: {}", e),
        )
    })?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, input);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("Failed to read file header: {}", e),
        )
    })?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid magic number {:?} - file not encrypted by this tool",
                magic
            ),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("Failed to read salt: {}", e),
        )
    })?;
    reader.read_exact(&mut base_nonce).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("Failed to read nonce: {}", e),
        )
    })?;

    let key = derive_key(
        password,
        &salt,
        DEFAULT_MEMORY_COST,
        DEFAULT_TIME_COST,
        DEFAULT_PARALLELISM,
    )?;
    let mut cur_nonce = base_nonce;

    let parent_dir = out_path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_file = TempFile::new_in(
        parent_dir,
        &out_path
            .file_name()
            .unwrap_or_else(|| "filecryption".as_ref())
            .to_string_lossy(),
        "tmp",
    )
    .map_err(|e| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Failed to create temp file in {}: {}", parent_dir.display(), e),
        )
    })?;
    let tmp_path = tmp_file.path().to_path_buf();
    let mut writer = BufWriter::with_capacity(CHUNK_SIZE, tmp_file.reopen()?);

    let aad = get_aad(&out_path);
    let mut buffer = vec![0u8; CHUNK_SIZE + TAG_LEN];
    let mut total_bytes = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        if n < TAG_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Truncated ciphertext block - possible file corruption",
            ));
        }

        let nonce = Nonce::from_slice(&cur_nonce)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid nonce structure"))?;
        let mut plaintext = vec![0u8; n - TAG_LEN];
        xchacha20poly1305::open(&key, &nonce, &buffer[..n], Some(&aad), &mut plaintext)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Authentication failed - data has been tampered with or corrupted"))?;
        writer.write_all(&plaintext)?;
        increment_nonce(&mut cur_nonce);
    }

    writer.flush()?;
    drop(writer);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io::Error::new(ErrorKind::PermissionDenied, format!("Failed to set secure permissions: {}", e)))?;
    }

    if force && out_path.exists() {
        fs::remove_file(&out_path).map_err(|e| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                format!("Failed to remove existing file: {}", e),
            )
        })?;
    }

    tmp_file
        .persist(&out_path)
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("File persistence failed: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&out_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| io::Error::new(ErrorKind::PermissionDenied, format!("Failed to set secure permissions: {}", e)))?;
    }

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
        return Err(io::Error::new(
            ErrorKind::Other,
            "Maximum directory depth exceeded - possible symlink loop",
        ));
    }

    let metadata = fs::metadata(dir).map_err(|e| {
        io::Error::new(
            match e.kind() {
                ErrorKind::NotFound => ErrorKind::NotFound,
                _ => ErrorKind::InvalidInput,
            },
            format!("Failed to access directory: {}", e),
        )
    })?;

    if !metadata.is_dir() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Path is not a directory",
        ));
    }

    let entries = fs::read_dir(dir).map_err(|e| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Failed to read directory contents: {}", e),
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to read directory entry: {}", e),
            )
        })?;
        let path = entry.path();

        if path.is_symlink() {
            continue;
        }

        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {
                walk_dir(&path, pw, encrypt, force, cli, depth + 1)?
            }
            Ok(metadata) if is_regular_file(&metadata) => {
                if encrypt {
                    encrypt_file(&path, pw, force, cli)?;
                } else if path.extension().map_or(false, |ext| ext == "enc") {
                    decrypt_file(&path, pw, force)?;
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: Skipping inaccessible file {}: {}",
                    path.display(),
                    e
                );
            }
            _ => continue,
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
        .output_len(32)
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
