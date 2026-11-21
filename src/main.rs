use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use orion::hazardous::aead::xchacha20poly1305::{Nonce, SecretKey as OrionSecretKey, XChaCha20Poly1305};
use rpassword::prompt_password;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"FCRYPT01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const PLAINTEXT_CHUNK_SIZE: usize = 64 * 1024;
const CIPHERTEXT_CHUNK_SIZE: usize = PLAINTEXT_CHUNK_SIZE + TAG_LEN;
const HEADER_SIZE: u64 = (MAGIC.len() + SALT_LEN + NONCE_LEN) as u64;
const MEMORY_COST: u32 = 1 << 16;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 1;

struct TempFile {
    path: PathBuf,
    active: bool,
}

impl TempFile {
    fn new(path: &Path) -> Self {
        TempFile {
            path: path.to_path_buf(),
            active: true,
        }
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

#[inline(always)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0 && a.len() == b.len()
}

fn increment_nonce_checked(nonce: &mut [u8; NONCE_LEN]) -> Result<(), &'static str> {
    for byte in nonce.iter_mut() {
        let (new, carry) = byte.overflowing_add(1);
        *byte = new;
        if !carry {
            return Ok(());
        }
    }
    Err("nonce wrap-around detected")
}

fn perform_dummy_open() {
    let zero_key = OrionSecretKey::from_slice(&[0u8; 32]).unwrap();
    let zero_nonce = Nonce::from_slice(&[0u8; NONCE_LEN]).unwrap();
    let dummy_ct = [0u8; TAG_LEN + 1];
    let mut dummy_out = [0u8; 1];
    let _ = XChaCha20Poly1305::open(&zero_key, &zero_nonce, &dummy_ct, None, &mut dummy_out);
}

#[cfg(unix)]
fn create_restricted(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_restricted(path: &Path) -> io::Result<File> {
    File::create(path)
}

fn atomic_replace(temp: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(all(windows, feature = "windows-replace"))]
    {
        if crate::windows_replace::replace_file_atomic(temp, dest).is_ok() {
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

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    let out_path = path.with_extension("enc");
    if out_path.exists() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Output file already exists.",
        ));
    }
    let tmp_path = out_path.with_extension("tmp");

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];

    getrandom::fill(&mut salt)
        .map_err(|e| io::Error::other(format!("Failed to acquire randomness for salt: {e}")))?;
    getrandom::fill(&mut base_nonce)
        .map_err(|e| io::Error::other(format!("Failed to acquire randomness for nonce: {e}")))?;

    let key = derive_key(password, &salt)?;

    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let tmp_guard = TempFile::new(&tmp_path);
    let output = create_restricted(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    writer.write_all(MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;
    writer.flush()?;

    let mut aad = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&base_nonce);

    let mut plaintext_buffer = Zeroizing::new(vec![0u8; PLAINTEXT_CHUNK_SIZE]);
    let mut ciphertext_buffer = Zeroizing::new(vec![0u8; CIPHERTEXT_CHUNK_SIZE]);
    let mut cur_nonce = base_nonce;

    loop {
        let n = reader.read(&mut plaintext_buffer[..])?;
        if n == 0 {
            break;
        }

        let nonce =
            Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        let ciphertext_len = n + TAG_LEN;

        XChaCha20Poly1305::seal(
            &key,
            &nonce,
            &plaintext_buffer[..n],
            Some(&aad),
            &mut ciphertext_buffer[..ciphertext_len],
        )
        .map_err(|_| io::Error::other("AEAD seal operation failed"))?;

        writer.write_all(&ciphertext_buffer[..ciphertext_len])?;

        increment_nonce_checked(&mut cur_nonce)
            .map_err(|_| io::Error::other("nonce wrap-around"))?;
    }

    writer.flush()?;
    drop(writer);

    atomic_replace(&tmp_path, &out_path)?;
    tmp_guard.persist();
    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension().and_then(|s| s.to_str()) != Some("enc") {
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

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut salt)?;
    reader.read_exact(&mut base_nonce)?;

    let mut aad = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&base_nonce);

    let key = derive_key(password, &salt)?;

    let magic_ok = constant_time_eq(&magic, MAGIC);

    if !magic_ok {
        perform_dummy_open();
        return Err(io::Error::new(ErrorKind::InvalidData, "Decryption failed"));
    }

    let mut cur_nonce = base_nonce;

    let out_path = path.with_extension("");
    let tmp_path = out_path.with_extension("tmp");
    let tmp_guard = TempFile::new(&tmp_path);
    let output = create_restricted(&tmp_path)?;
    let mut writer = BufWriter::new(output);

    let ciphertext_len = file_len - HEADER_SIZE;
    let full_chunks = ciphertext_len / CIPHERTEXT_CHUNK_SIZE as u64;
    let final_chunk_size = (ciphertext_len % CIPHERTEXT_CHUNK_SIZE as u64) as usize;

    let mut ciphertext_chunk = Zeroizing::new(vec![0u8; CIPHERTEXT_CHUNK_SIZE]);
    let mut plaintext_chunk = Zeroizing::new(vec![0u8; PLAINTEXT_CHUNK_SIZE]);

    for _ in 0..full_chunks {
        reader.read_exact(&mut ciphertext_chunk[..])?;

        let nonce =
            Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        XChaCha20Poly1305::open(
            &key,
            &nonce,
            &ciphertext_chunk[..],
            Some(&aad),
            &mut plaintext_chunk[..],
        )
        .map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "Authentication failed: incorrect password or corrupted data.",
            )
        })?;

        writer.write_all(&plaintext_chunk[..])?;

        increment_nonce_checked(&mut cur_nonce)
            .map_err(|_| io::Error::other("nonce wrap-around"))?;
    }

    if final_chunk_size > 0 {
        if final_chunk_size < TAG_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Final ciphertext chunk is too short for a valid tag.",
            ));
        }
        let mut final_ciphertext_chunk = Zeroizing::new(vec![0u8; final_chunk_size]);
        reader.read_exact(&mut final_ciphertext_chunk[..])?;

        let nonce =
            Nonce::from_slice(&cur_nonce).map_err(|_| io::Error::other("Invalid nonce state"))?;

        let mut final_plaintext_chunk = Zeroizing::new(vec![0u8; final_chunk_size - TAG_LEN]);
        XChaCha20Poly1305::open(
            &key,
            &nonce,
            &final_ciphertext_chunk[..],
            Some(&aad),
            &mut final_plaintext_chunk[..],
        )
        .map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "Authentication failed on final chunk: incorrect password or corrupted data.",
            )
        })?;

        writer.write_all(&final_plaintext_chunk[..])?;
    }

    writer.flush()?;
    drop(writer);

    atomic_replace(&tmp_path, &out_path)?;
    tmp_guard.persist();
    Ok(())
}

fn walk_dir(dir: &Path, pw: &Zeroizing<String>, encrypt: bool) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;

        if metadata.is_symlink() {
            continue;
        }

        if metadata.is_dir() {
            walk_dir(&path, pw, encrypt)?;
        } else if metadata.is_file() {
            if encrypt {
                encrypt_file(&path, pw)?;
            } else {
                decrypt_file(&path, pw)?;
            }
        }
    }
    Ok(())
}

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
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn replace_file_atomic(src: &Path, dest: &Path) -> io::Result<()> {
        let src_w = to_wide(src.as_os_str());
        let dest_w = to_wide(dest.as_os_str());

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
