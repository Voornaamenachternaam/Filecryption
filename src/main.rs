// src/main.rs
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};
use getrandom::getrandom;
use rpassword::prompt_password;
use zeroize::Zeroizing;

/// The magic header identifying an encrypted file.
const MAGIC: &[u8; 8] = b"FCRYPT01";
/// Length of the random salt used in key derivation.
const SALT_LEN: usize = 16;
/// Length of the XChaCha20 nonce.
const NONCE_LEN: usize = 24;
/// Length of the Poly1305 authentication tag.
const TAG_LEN: usize = 16;
/// Size of the plaintext I/O buffer for streaming file operations.
const PLAINTEXT_CHUNK_SIZE: usize = 64 * 1024;
/// Size of a full ciphertext chunk (plaintext + tag).
const CIPHERTEXT_CHUNK_SIZE: usize = PLAINTEXT_CHUNK_SIZE + TAG_LEN;
/// Total header size (MAGIC + SALT + NONCE).
const HEADER_SIZE: u64 = (MAGIC.len() + SALT_LEN + NONCE_LEN) as u64;
/// Argon2id memory cost parameter (in KiB).
const MEMORY_COST: u32 = 1 << 16; // 64 MiB
/// Argon2id time cost parameter.
const TIME_COST: u32 = 3;
/// Argon2id parallelism parameter.
const PARALLELISM: u32 = 1;

/// RAII guard for a temporary file, ensuring its removal on drop unless persisted.
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

/// Command Line Interface definition using Clap 4.5+
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
    Encrypt { file: PathBuf },
    Decrypt { file: PathBuf },
    EncryptDir { dir: PathBuf },
    DecryptDir { dir: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { file } => {
            let pw = prompt_password_secure(true).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {e}");
                exit(1);
            });
            if let Err(e) = encrypt_file(&file, &pw) {
                eprintln!("Encryption of '{}' failed: {e}", file.display());
                exit(1);
            }
        }
        Command::Decrypt { file } => {
            let pw = prompt_password_secure(false).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {e}");
                exit(1);
            });
            if let Err(e) = decrypt_file(&file, &pw) {
                eprintln!("Decryption of '{}' failed: {e}", file.display());
                exit(1);
            }
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password_secure(true).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {e}");
                exit(1);
            });
            if let Err(e) = walk_dir(&dir, &pw, true) {
                eprintln!("Directory encryption of '{}' failed: {e}", dir.display());
                exit(1);
            }
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password_secure(false).unwrap_or_else(|e| {
                eprintln!("Password prompt failed: {e}");
                exit(1);
            });
            if let Err(e) = walk_dir(&dir, &pw, false) {
                eprintln!("Directory decryption of '{}' failed: {e}", dir.display());
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

/// Constant-time equality for byte slices (returns true if equal).
#[inline(always)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Increment nonce and detect full wrap-around (error on wrap).
fn increment_nonce_checked(nonce: &mut [u8; NONCE_LEN]) -> Result<(), &'static str> {
    for byte in nonce.iter_mut().rev() {
        let (new, carry) = byte.overflowing_add(1);
        *byte = new;
        if !carry {
            return Ok(());
        }
    }
    // wrap-around happened — treat as fatal (defensive)
    Err("nonce wrap-around detected")
}

/// Helper: perform a small dummy AEAD open to normalize timing (used when header/magic mismatch).
fn perform_dummy_open() {
    // This function should not panic; ignore any errors. Purpose: consume some AEAD-time.
    let zero_key = OrionSecretKey::from_slice(&[0u8; 32]);
    if let Ok(k) = zero_key {
        if let Ok(n) = Nonce::from_slice(&[0u8; NONCE_LEN]) {
            // Small dummy ciphertext (must be at least TAG_LEN to be plausible)
            let dummy_ct = vec![0u8; TAG_LEN + 1];
            let mut _out = Vec::new();
            let _ = xchacha20poly1305::open(&k, &n, &dummy_ct, None, &mut _out);
        }
    }
}

/// Cross-platform atomic replace helper.
/// On Windows, when the feature `windows-replace` is enabled we call ReplaceFileW via windows-sys.
/// Otherwise fall back to robust rename semantics with fallback.
fn atomic_replace(temp: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(all(windows, feature = "windows-replace"))]
    {
        if let Err(e) = crate::windows_replace::replace_file_atomic(temp, dest) {
            eprintln!("windows ReplaceFileW failed: {}. Falling back to rename-remove-rename.", e);
        } else {
            return Ok(());
        }
    }

    match fs::rename(temp, dest) {
        Ok(()) => Ok(()),
        Err(e) => {
            if dest.exists() {
                fs::remove_file(dest)?;
                fs::rename(temp, dest)?;
                Ok(())
            } else {
                Err(e)
            }
        }
    }
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
    // Create temp in same directory to ensure rename/replace works on same volume.
    let tmp_path = out_path.with_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];

    // Use getrandom for cryptographic randomness (OS RNG)
    getrandom(&mut salt).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to acquire randomness for salt: {}", e),
        )
    })?;
    getrandom(&mut base_nonce).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to acquire randomness for nonce: {}", e),
        )
    })?;

    // Derive key once (normal flow).
    let key = derive_key(password, &salt)?;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let tmp_file_handler = TempFile::create(&tmp_path)?;
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    // Write the file header (MAGIC | salt | base_nonce).
    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;
    writer.flush()?; // flush header so AAD matches file layout if someone inspects file early.

    // Compose AAD = header bytes so header gets authenticated.
    let mut aad = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&base_nonce);

    // Use a pre-allocated buffer for plaintext.
    let mut plaintext_buffer = vec![0u8; PLAINTEXT_CHUNK_SIZE];
    let mut cur_nonce = base_nonce;

    loop {
        let n = reader.read(&mut plaintext_buffer)?;
        if n == 0 {
            break;
        }

        let nonce = Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        // Create an empty buffer with pre-allocated capacity for the ciphertext + tag.
        let mut ciphertext_chunk = Vec::with_capacity(n + TAG_LEN);
        xchacha20poly1305::seal(
            &key,
            &nonce,
            &plaintext_buffer[..n],
            Some(&aad),
            &mut ciphertext_chunk,
        )
        .map_err(|_| io::Error::other("AEAD seal operation failed"))?;

        writer.write_all(&ciphertext_chunk)?;

        // Advance the nonce for the next chunk. Error if wrap-around would happen.
        increment_nonce_checked(&mut cur_nonce).map_err(|_| io::Error::other("nonce wrap-around"))?;
    }

    writer.flush()?;
    drop(writer);

    // Atomic replace (platform-specific inside)
    atomic_replace(&tmp_path, &out_path)?;
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
    let file_len = input.metadata()?.len();

    if file_len < HEADER_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "File is too short to contain a valid header.",
        ));
    }

    let mut reader = BufReader::new(&input);

    // Read header fields
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    // Compose AAD (same bytes used during encryption).
    let mut aad = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&base_nonce);

    // ALWAYS derive Argon2 key (prevents timing oracle revealing header mismatch vs KDF cost).
    let key = derive_key(password, &salt)?;

    // Constant-time check of MAGIC
    let magic_ok = constant_time_eq(&magic, MAGIC);

    // If magic mismatch: perform a dummy AEAD open to consume similar AEAD-time and return a generic error.
    if !magic_ok {
        // consume some AEAD time: call dummy open (silent)
        perform_dummy_open();
        return Err(io::Error::new(ErrorKind::InvalidData, "Decryption failed"));
    }

    // Continue normally
    let mut cur_nonce = base_nonce;

    let out_path = path.with_extension("");
    let tmp_path = out_path.with_extension("tmp");
    let tmp_file_handler = TempFile::create(&tmp_path)?;
    let output = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    // Calculate ciphertext length and chunk structure.
    let ciphertext_len = file_len - HEADER_SIZE;
    let full_chunks = ciphertext_len / CIPHERTEXT_CHUNK_SIZE as u64;
    let final_chunk_size = (ciphertext_len % CIPHERTEXT_CHUNK_SIZE as u64) as usize;

    // Process full chunks.
    for _ in 0..full_chunks {
        let mut ciphertext_chunk = vec![0u8; CIPHERTEXT_CHUNK_SIZE];
        reader.read_exact(&mut ciphertext_chunk)?;

        let nonce = Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        let mut plaintext_chunk = Vec::with_capacity(PLAINTEXT_CHUNK_SIZE);
        xchacha20poly1305::open(&key, &nonce, &ciphertext_chunk, Some(&aad), &mut plaintext_chunk)
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "Authentication failed: incorrect password or corrupted data.",
                )
            })?;

        writer.write_all(&plaintext_chunk)?;

        // Advance the nonce for the next chunk.
        increment_nonce_checked(&mut cur_nonce).map_err(|_| io::Error::other("nonce wrap-around"))?;
    }

    // Process the final, potentially short, chunk.
    if final_chunk_size > 0 {
        if final_chunk_size < TAG_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Final ciphertext chunk is too short for a valid tag.",
            ));
        }
        let mut final_ciphertext_chunk = vec![0u8; final_chunk_size];
        reader.read_exact(&mut final_ciphertext_chunk)?;

        let nonce = Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        let mut final_plaintext_chunk = Vec::with_capacity(final_chunk_size - TAG_LEN);
        xchacha20poly1305::open(
            &key,
            &nonce,
            &final_ciphertext_chunk,
            Some(&aad),
            &mut final_plaintext_chunk,
        )
        .map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "Authentication failed on final chunk: incorrect password or corrupted data.",
            )
        })?;

        writer.write_all(&final_plaintext_chunk)?;
    }

    writer.flush()?;
    drop(writer);

    atomic_replace(&tmp_path, &out_path)?;
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
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(32)).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("Argon2 parameter validation failed: {}", e),
        )
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(password.as_bytes(), salt, raw_key.as_mut())
        .map_err(|e| io::Error::other(format!("Argon2 key derivation failed: {}", e)))?;

    OrionSecretKey::from_slice(raw_key.as_ref())
        .map_err(|_| io::Error::other("Failed to initialize Orion secret key"))
}

#[cfg(all(windows, feature = "windows-replace"))]
mod windows_replace {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    // windows-sys = "0.61.2" is expected in Cargo.toml under [dependencies] as optional.
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Replace dest with src atomically using ReplaceFileW.
    pub fn replace_file_atomic(src: &Path, dest: &Path) -> io::Result<()> {
        let src_w = to_wide(src.as_os_str());
        let dest_w = to_wide(dest.as_os_str());

        // ReplaceFileW(dest, src, NULL, 0, NULL, NULL)
        let ok = unsafe {
            ReplaceFileW(
                dest_w.as_ptr(),
                src_w.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
