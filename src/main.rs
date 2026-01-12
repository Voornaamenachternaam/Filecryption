use std::fs::{File, OpenOptions, read_dir};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

// Platform-specific imports for file permissions
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use orion::aead::SecretKey;
use orion::aead::streaming::*;
use orion::kdf;
use rpassword::read_password;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// File that stores serialized params (salt + memory parameter)
const FILEPARAM: &str = ".parameters.txt";
/// XChaCha20 nonce size (Orion uses 24 bytes for XChaCha)
const NONCE_LEN: usize = 24;
/// Suffix appended on encrypted files (for safety)
const ENCRYPTSUFFIX: &str = "_encrypted";

/// Chunk size used for streaming (must be reasonably small to avoid memory spikes).
const CHUNK_SIZE: usize = 128 * 1024; // 128 KiB

/// Minimum secure Argon2 parameters
const MIN_MEMORY_KB: u32 = 65536;
const MIN_ITERATIONS: u32 = 10; // Minimum iterations for security
const DEFAULT_MEMORY_KB: u32 = 4096; // 4MB default

#[derive(Parser, Debug)]
#[command(author, version, about = "Filecryption (streaming main.rs)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file (writes <filename>_encrypted)
    Encrypt {
        /// Input file to encrypt
        file: PathBuf,
    },

    /// Decrypt a file produced by this tool
    Decrypt {
        /// Input file to decrypt (should have nonce + chunked ciphertext)
        file: PathBuf,
    },

    /// Recursively encrypt all files in a directory (non-hidden)
    EncryptDir { dir: PathBuf },

    /// Recursively decrypt a directory produced by EncryptDir
    DecryptDir { dir: PathBuf },
}

/// Secure password wrapper that zeroizes on drop
#[derive(ZeroizeOnDrop)]
struct SecurePassword {
    inner: String,
}

impl SecurePassword {
    fn new(password: String) -> Self {
        Self { inner: password }
    }

    fn as_str(&self) -> &str {
        &self.inner
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { file } => {
            let pw = prompt_for_password(true);
            if let Err(e) = encrypt_path(file, &pw) {
                eprintln!("Encryption failed: {e}");
                exit(1);
            }
        }
        Commands::Decrypt { file } => {
            let pw = prompt_for_password(false);
            if let Err(e) = decrypt_path(file, &pw) {
                eprintln!("Decryption failed: {e}");
                exit(1);
            }
        }
        Commands::EncryptDir { dir } => {
            let pw = prompt_for_password(true);
            if let Err(e) = traverse_and_encrypt(dir, &pw) {
                eprintln!("Directory encryption failed: {e}");
                exit(1);
            }
        }
        Commands::DecryptDir { dir } => {
            let pw = prompt_for_password(false);
            if let Err(e) = traverse_and_decrypt(dir, &pw) {
                eprintln!("Directory decryption failed: {e}");
                exit(1);
            }
        }
    }
}

/// Securely prompt for password with validation
fn prompt_for_password(for_encrypt: bool) -> SecurePassword {
    if for_encrypt {
        println!("Enter a password to derive the encryption key (will be used with Argon2i):");
        let mut pw = read_password().expect("Failed to read password");

        // Validate password strength
        if let Err(e) = validate_password_strength(&pw) {
            pw.zeroize();
            eprintln!("Password validation failed: {e}");
            exit(1);
        }

        println!("Confirm password:");
        let mut pw2 = read_password().expect("Failed to read password");
        if pw != pw2 {
            pw.zeroize();
            pw2.zeroize();
            eprintln!("Passwords do not match.");
            exit(1);
        }
        pw2.zeroize();
        SecurePassword::new(pw)
    } else {
        println!("Enter the decryption password:");
        let pw = read_password().expect("Failed to read password");
        SecurePassword::new(pw)
    }
}

/// Validate password meets minimum security requirements
fn validate_password_strength(password: &str) -> Result<(), &'static str> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters long");
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit");
    }
    Ok(())
}

/// Top-level path encrypt helper
fn encrypt_path(path: &Path, password: &SecurePassword) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::other(
            "encrypt_path: expected file, got directory",
        ));
    }
    let out_path = path.with_file_name(format!(
        "{}{}",
        path.file_name().unwrap().to_string_lossy(),
        ENCRYPTSUFFIX
    ));
    // Generate salt
    let salt = kdf::Salt::default(); // 16 bytes
    // Use secure Argon2 parameters
    let mem_param: u32 = DEFAULT_MEMORY_KB;
    let iter_param: u32 = MIN_ITERATIONS;
    write_param_file(path, mem_param, &salt)?;

    // derive the key
    let secret_key =
        derive_secret_key_from_password(password.as_str(), &salt, iter_param, mem_param)?;
    // encrypt streaming
    encrypt_file_streaming(path, &out_path, &secret_key)?;
    println!("Encrypted {} -> {}", path.display(), out_path.display());
    Ok(())
}

/// Top-level path decrypt helper
fn decrypt_path(path: &Path, password: &SecurePassword) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::other(
            "decrypt_path: expected file, got directory",
        ));
    }
    // read parameters file (sidecar)
    let parent = path.parent().unwrap_or(Path::new("."));
    let param_file = parent.join(FILEPARAM);
    let (iter_param, mem_param, salt) = read_param_file(&param_file)?;
    // derive
    let secret_key =
        derive_secret_key_from_password(password.as_str(), &salt, iter_param, mem_param)?;
    // decrypt streaming
    // output path: remove ENCRYPTSUFFIX if present
    let out_path = if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        if let Some(stripped) = name.strip_suffix(ENCRYPTSUFFIX) {
            use std::path::Component;
            let stripped_path = Path::new(stripped);
            let mut components = stripped_path.components();
            if !(components
                .next()
                .is_some_and(|c| matches!(c, Component::Normal(_)))
                && components.next().is_none())
            {
                return Err(io::Error::other(
                    "invalid output filename: contains path components",
                ));
            }
            stripped_path.to_path_buf()
        } else {
            // append .decrypted if suffix not present
            Path::new(&format!("{}.decrypted", name)).to_path_buf()
        }
    } else {
        PathBuf::from("decrypted_output")
    };
    let out_full = path.with_file_name(out_path);
    decrypt_file_streaming(path, &out_full, &secret_key)?;
    println!("Decrypted {} -> {}", path.display(), out_full.display());
    Ok(())
}

/// Walk a directory recursively encrypting files (non-hidden)
fn traverse_and_encrypt(dir: &Path, password: &SecurePassword) -> io::Result<()> {
    for entry in read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            traverse_and_encrypt(&p, password)?;
        } else {
            // skip our param file and skip already encrypted files
            if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                if fname == FILEPARAM {
                    continue;
                }
                if fname.ends_with(ENCRYPTSUFFIX) {
                    continue;
                }
            }
            encrypt_path(&p, password)?;
        }
    }
    Ok(())
}

/// Walk a directory recursively decrypting files (non-hidden)
fn traverse_and_decrypt(dir: &Path, password: &SecurePassword) -> io::Result<()> {
    for entry in read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            traverse_and_decrypt(&p, password)?;
        } else if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
            if fname == FILEPARAM {
                continue;
            }
            // only attempt decrypt on files with ENCRYPTSUFFIX
            if fname.ends_with(ENCRYPTSUFFIX) {
                decrypt_path(&p, password)?;
            }
        }
    }
    Ok(())
}

/// Write a tiny parameters file next to the input file for decryption (mem:param:salt)
/// Create a file with secure permissions (cross-platform)
fn create_secure_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    #[cfg(windows)]
    {
        // On Windows, we rely on the default file permissions
        // and the user's file system permissions
        // Additional Windows-specific security could be added here if needed
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Fallback for other platforms - use default permissions
    }

    options.open(path)
}

fn write_param_file(path: &Path, mem: u32, salt: &kdf::Salt) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let param_file = parent.join(FILEPARAM);

    // Create parameter file with secure permissions (600)
    let mut f = create_secure_file(&param_file)?;
    let b64_salt = general_purpose::STANDARD.encode(salt.as_ref());
    let line = format!("{}:{}\n", mem, b64_salt);
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Read param file (mem, iterations, salt)
fn read_param_file(param_file: &Path) -> io::Result<(u32, u32, kdf::Salt)> {
    let mut buf = String::new();
    let mut f = File::open(param_file)?;
    f.read_to_string(&mut buf)?;
    // expected format: "<mem>:<base64salt>\n"
    let parts: Vec<&str> = buf.trim().split(':').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "param file malformed",
        ));
    }
    let mem: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mem param"))?;
    let salt_bytes = general_purpose::STANDARD
        .decode(parts[1].trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid base64 salt"))?;
    let salt = kdf::Salt::from_slice(&salt_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid salt length"))?;

    // Validate security parameters
    if mem < MIN_MEMORY_KB {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "memory parameter below security minimum",
        ));
    }

    let iterations: u32 = MIN_ITERATIONS; // Use secure minimum, no backward compatibility for weak parameters
    Ok((iterations, mem, salt))
}

/// Derive an orion secret key from a password and salt using orion::kdf::derive_key
fn derive_secret_key_from_password(
    password: &str,
    salt: &kdf::Salt,
    iterations: u32,
    memory_kib: u32,
) -> io::Result<SecretKey> {
    // Validate parameters meet security minimums
    if memory_kib < MIN_MEMORY_KB || iterations < MIN_ITERATIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cryptographic parameters below security minimum",
        ));
    }

    // convert to kdf::Password wrapper
    let password_kdf = kdf::Password::from_slice(password.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password invalid"))?;
    // desired length for key = 32 bytes (XChaCha20-Poly1305 key size)
    let desired_len = 32u32;
    let dk = kdf::derive_key(&password_kdf, salt, iterations, memory_kib, desired_len)
        .map_err(|_| io::Error::other("kdf derive_key failed"))?;
    Ok(dk)
}

/// Encrypt a file using streaming AEAD.
/// File format:
/// [nonce bytes (NONCE_LEN)][u64_be len-of-chunk1][chunk1 bytes][u64_be len-of-chunk2][chunk2 bytes]...
fn encrypt_file_streaming(
    in_path: &Path,
    out_path: &Path,
    secret_key: &SecretKey,
) -> io::Result<()> {
    let infile = File::open(in_path)?;
    let mut rdr = BufReader::new(infile);

    // Create output file with secure permissions (600)
    let outfile = create_secure_file(out_path)?;
    let mut wtr = BufWriter::new(outfile);
    let (mut sealer, nonce) = StreamSealer::new(secret_key)
        .map_err(|_| io::Error::other("Failed to create StreamSealer"))?;

    // Write nonce bytes at start
    wtr.write_all(nonce.as_ref())?;

    // Use zeroizing buffer for sensitive data
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    loop {
        let read = rdr.read(&mut buffer)?;
        if read == 0 {
            // nothing more to read: send a zero-length Finish message to mark stream end
            let encrypted_chunk = sealer
                .seal_chunk(&[], &StreamTag::Finish)
                .map_err(|_| io::Error::other("seal_chunk failed"))?;
            let len = encrypted_chunk.len() as u64;
            wtr.write_all(&len.to_be_bytes())?;
            wtr.write_all(&encrypted_chunk)?;
            break;
        } else {
            // Use message tag for each chunk; we rely on final zero-length Finish chunk above
            let encrypted_chunk = sealer
                .seal_chunk(&buffer[..read], &StreamTag::Message)
                .map_err(|_| io::Error::other("seal_chunk failed"))?;
            let len = encrypted_chunk.len() as u64;
            wtr.write_all(&len.to_be_bytes())?;
            wtr.write_all(&encrypted_chunk)?;
        }
    }

    // Ensure data is flushed
    wtr.flush()?;
    Ok(())
}

/// Decrypt file that follows the format produced by encrypt_file_streaming
fn decrypt_file_streaming(
    in_path: &Path,
    out_path: &Path,
    secret_key: &SecretKey,
) -> io::Result<()> {
    let infile = File::open(in_path)?;
    let mut rdr = BufReader::new(infile);

    // Create output file with secure permissions (600)
    let outfile = create_secure_file(out_path)?;
    let mut wtr = BufWriter::new(outfile);
    // Read nonce
    let mut nonce_buf = vec![0u8; NONCE_LEN];
    rdr.read_exact(&mut nonce_buf)?;
    let nonce = Nonce::from_slice(&nonce_buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce"))?;
    let mut opener = StreamOpener::new(secret_key, &nonce)
        .map_err(|_| io::Error::other("Failed to create StreamOpener"))?;

    // Loop: read u64 length then that many bytes
    loop {
        let mut lenbuf = [0u8; 8];
        match rdr.read_exact(&mut lenbuf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // no more chunks; done
                break;
            }
            Err(e) => return Err(e),
        }
        let chunk_len = u64::from_be_bytes(lenbuf) as usize;
        if chunk_len == 0 {
            // nothing to do
            continue;
        }
        // Use zeroizing buffer for sensitive data
        let mut chunk = zeroize::Zeroizing::new(vec![0u8; chunk_len]);
        rdr.read_exact(&mut chunk)?;
        let (plain, tag) = opener.open_chunk(&chunk).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "open_chunk failed: authentication error",
            )
        })?;
        // Write decrypted data and ensure it's cleared from memory
        wtr.write_all(&plain)?;
        if tag == StreamTag::Finish {
            break;
        }
    }

    wtr.flush()?;
    Ok(())
}
