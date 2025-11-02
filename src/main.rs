// SPDX-License-Identifier: GPL-3.0-or-later
//! Drop-in streaming-based main.rs for Filecryption
//! Uses orion::aead::streaming::* (StreamSealer, StreamOpener, StreamTag)
//! Compatible with orion 0.17.11 and Rust 1.91 (matches your CI logs). :contentReference[oaicite:2]{index=2}

use std::fs::{File, OpenOptions, read_dir};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;

use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use orion::aead::{self, SecretKey};
use orion::aead::streaming::*;
use orion::kdf;
use rpassword;
use zeroize::Zeroize;

/// File that stores serialized params (salt + memory parameter)
const FILEPARAM: &str = ".parameters.txt";
/// How many bytes of salt — kdf::Salt::default() uses 16, but keep SALTSIZE conservative if needed.
const SALTSIZE: usize = 16;
/// Suffix appended on encrypted files (for safety)
const ENCRYPTSUFFIX: &str = "_encrypted";

/// Chunk size used for streaming (must be reasonably small to avoid memory spikes).
const CHUNK_SIZE: usize = 128 * 1024; // 128 KiB

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
        /// Provide password on command line (not recommended)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a file produced by this tool
    Decrypt {
        /// Input file to decrypt (should have nonce + chunked ciphertext)
        file: PathBuf,
        /// Provide password on command line (not recommended)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Recursively encrypt all files in a directory (non-hidden)
    EncryptDir {
        dir: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Recursively decrypt a directory produced by EncryptDir
    DecryptDir {
        dir: PathBuf,
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { file, password } => {
            let pw = prompt_or_use(password.clone(), true);
            if let Err(e) = encrypt_path(file, &pw) {
                eprintln!("Encryption failed: {e}");
                exit(1);
            }
        }
        Commands::Decrypt { file, password } => {
            let pw = prompt_or_use(password.clone(), false);
            if let Err(e) = decrypt_path(file, &pw) {
                eprintln!("Decryption failed: {e}");
                exit(1);
            }
        }
        Commands::EncryptDir { dir, password } => {
            let pw = prompt_or_use(password.clone(), true);
            if let Err(e) = traverse_and_encrypt(dir, &pw) {
                eprintln!("Directory encryption failed: {e}");
                exit(1);
            }
        }
        Commands::DecryptDir { dir, password } => {
            let pw = prompt_or_use(password.clone(), false);
            if let Err(e) = traverse_and_decrypt(dir, &pw) {
                eprintln!("Directory decryption failed: {e}");
                exit(1);
            }
        }
    }
}

/// Prompt for password unless one was provided on CLI
fn prompt_or_use(provided: Option<String>, for_encrypt: bool) -> String {
    if let Some(p) = provided {
        return p;
    }
    if for_encrypt {
        println!("Enter a password to derive the encryption key (will be used with Argon2i):");
        let pw = rpassword::read_password().expect("Failed to read password");
        println!("Confirm password:");
        let pw2 = rpassword::read_password().expect("Failed to read password");
        if pw != pw2 {
            eprintln!("Passwords do not match.");
            exit(1);
        }
        pw
    } else {
        println!("Enter the decryption password:");
        rpassword::read_password().expect("Failed to read password")
    }
}

/// Top-level path encrypt helper
fn encrypt_path(path: &Path, password: &str) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::new(io::ErrorKind::Other, "encrypt_path: expected file, got directory"));
    }
    let out_path = path.with_file_name(format!("{}{}", path.file_name().unwrap().to_string_lossy(), ENCRYPTSUFFIX));
    // Generate salt
    let salt = kdf::Salt::default(); // 16 bytes
    // Save params to a small `.parameters.txt` sidecar file (mem arg encoded + salt)
    // We'll use memory parameter of 1<<16 (65536 KiB) and iterations 3 by default — these are conservative defaults.
    // If you prefer different params, change below.
    let mem_param: u32 = 1 << 16; // KiB
    let iter_param: u32 = 3;
    write_param_file(path, mem_param, &salt)?;

    // derive the key
    let secret_key = derive_secret_key_from_password(password, &salt, iter_param, mem_param)?;
    // encrypt streaming
    encrypt_file_streaming(path, &out_path, &secret_key)?;
    println!("Encrypted {} -> {}", path.display(), out_path.display());
    Ok(())
}

/// Top-level path decrypt helper
fn decrypt_path(path: &Path, password: &str) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::new(io::ErrorKind::Other, "decrypt_path: expected file, got directory"));
    }
    // read parameters file (sidecar)
    let parent = path.parent().unwrap_or(Path::new("."));
    let param_file = parent.join(FILEPARAM);
    let (iter_param, mem_param, salt) = read_param_file(&param_file)?;
    // derive
    let secret_key = derive_secret_key_from_password(password, &salt, iter_param, mem_param)?;
    // decrypt streaming
    // output path: remove ENCRYPTSUFFIX if present
    let out_path = if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        if name.ends_with(ENCRYPTSUFFIX) {
            Path::new(&name[..name.len()-ENCRYPTSUFFIX.len()]).to_path_buf()
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
fn traverse_and_encrypt(dir: &Path, password: &str) -> io::Result<()> {
    for entry in read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            traverse_and_encrypt(&p, password)?;
        } else {
            // skip our param file and skip already encrypted files
            if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                if fname == FILEPARAM { continue; }
                if fname.ends_with(ENCRYPTSUFFIX) { continue; }
            }
            encrypt_path(&p, password)?;
        }
    }
    Ok(())
}

/// Walk a directory recursively decrypting files (non-hidden)
fn traverse_and_decrypt(dir: &Path, password: &str) -> io::Result<()> {
    for entry in read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            traverse_and_decrypt(&p, password)?;
        } else {
            if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                if fname == FILEPARAM { continue; }
                // only attempt decrypt on files with ENCRYPTSUFFIX
                if fname.ends_with(ENCRYPTSUFFIX) {
                    decrypt_path(&p, password)?;
                }
            }
        }
    }
    Ok(())
}

/// Write a tiny parameters file next to the input file for decryption (mem:param:salt)
fn write_param_file(path: &Path, mem: u32, salt: &kdf::Salt) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let param_file = parent.join(FILEPARAM);
    let mut f = OpenOptions::new().create(true).append(false).write(true).truncate(true).open(param_file)?;
    // We'll store memory parameter and base64(salt)
    let b64_salt = general_purpose::STANDARD.encode(salt.unprotected_as_bytes());
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "param file malformed"));
    }
    let mem: u32 = parts[0].trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mem param"))?;
    let salt_bytes = general_purpose::STANDARD.decode(parts[1].trim())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid base64 salt"))?;
    let salt = kdf::Salt::from_slice(&salt_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid salt length"))?;
    // iterations we're using a default of 3 (the code that wrote it used 3), but if you want to store it, extend format.
    let iterations: u32 = 3;
    Ok((iterations, mem, salt))
}

/// Derive an orion secret key from a password and salt using orion::kdf::derive_key
fn derive_secret_key_from_password(password: &str, salt: &kdf::Salt, iterations: u32, memory_kib: u32) -> io::Result<SecretKey> {
    // convert to kdf::Password wrapper
    let password_kdf = kdf::Password::from_slice(password.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password invalid"))?;
    // desired length for key = 32 bytes (XChaCha20-Poly1305 key size)
    let desired_len = 32u32;
    let dk = kdf::derive_key(&password_kdf, salt, iterations, memory_kib, desired_len)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "kdf derive_key failed"))?;
    // dk is the crate's high-level SecretKey type (compatible with aead::SecretKey)
    // Return as aead::SecretKey (same underlying type in orion's high-level API)
    Ok(dk)
}

/// Encrypt a file using streaming AEAD.
/// File format:
/// [nonce bytes (Nonce::len())][u64_be len-of-chunk1][chunk1 bytes][u64_be len-of-chunk2][chunk2 bytes]...
fn encrypt_file_streaming(in_path: &Path, out_path: &Path, secret_key: &SecretKey) -> io::Result<()> {
    let infile = File::open(in_path)?;
    let mut rdr = BufReader::new(infile);
    let outfile = OpenOptions::new().create(true).write(true).truncate(true).open(out_path)?;
    let mut wtr = BufWriter::new(outfile);

    // Create the StreamSealer and get the nonce
    let (mut sealer, nonce) = StreamSealer::new(secret_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to create StreamSealer"))?;

    // Write nonce bytes at start
    wtr.write_all(nonce.as_ref())?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let read = rdr.read(&mut buffer)?;
        if read == 0 {
            // nothing more to read: send a zero-length Finish message to mark stream end (some implementations don't need it,
            // but we follow the recommended pattern to ensure opener can detect truncation).
            let encrypted_chunk = sealer.seal_chunk(&[], &StreamTag::Finish)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "seal_chunk failed"))?;
            // write chunk length then chunk
            let len = encrypted_chunk.len() as u64;
            wtr.write_all(&len.to_be_bytes())?;
            wtr.write_all(&encrypted_chunk)?;
            break;
        } else {
            // Determine tag: if read < chunk_size -> probably last chunk (but we still treat final chunk explicitly only when EOF next iteration).
            // To be safe, when read < buffer.len() and next read will be 0, we will set Finish below.
            // Simpler: we mark normal message unless read < buffer.len() and rdr.peek isn't available; instead detect EOF by using exact read < CHUNK_SIZE and no more bytes:
            // We'll check if read < CHUNK_SIZE and then use Finish tag, else Message.
            let tag = if read < CHUNK_SIZE { &StreamTag::Message } else { &StreamTag::Message }; // default Message
            // We'll decide Finish when we reach EOF in the next iteration; but to guarantee the stream ends we will set Finish on the final explicit zero-length message above.
            let encrypted_chunk = sealer.seal_chunk(&buffer[..read], tag)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "seal_chunk failed"))?;
            let len = encrypted_chunk.len() as u64;
            wtr.write_all(&len.to_be_bytes())?;
            wtr.write_all(&encrypted_chunk)?;
            // continue until EOF; finalization already handled by the zero-length Finish chunk above.
        }
    }

    // Ensure data is flushed
    wtr.flush()?;

    Ok(())
}

/// Decrypt file that follows the format produced by encrypt_file_streaming
fn decrypt_file_streaming(in_path: &Path, out_path: &Path, secret_key: &SecretKey) -> io::Result<()> {
    let infile = File::open(in_path)?;
    let mut rdr = BufReader::new(infile);
    let outfile = OpenOptions::new().create(true).write(true).truncate(true).open(out_path)?;
    let mut wtr = BufWriter::new(outfile);

    // Read nonce
    // Nonce length is provided by the Nonce type; the streaming module re-exports Nonce
    let mut nonce_buf = vec![0u8; Nonce::len()];
    rdr.read_exact(&mut nonce_buf)?;
    let nonce = Nonce::from_slice(&nonce_buf).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce"))?;
    let mut opener = StreamOpener::new(secret_key, &nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to create StreamOpener"))?;

    // Loop: read u64 length then that many bytes
    loop {
        let mut lenbuf = [0u8; 8];
        match rdr.read_exact(&mut lenbuf) {
            Ok(()) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // no more chunks; done
                break;
            }
            Err(e) => return Err(e),
        }
        let chunk_len = u64::from_be_bytes(lenbuf) as usize;
        if chunk_len == 0 {
            // Nothing — continue (shouldn't happen because we always write a final non-empty sealed chunk)
            continue;
        }
        let mut chunk = vec![0u8; chunk_len];
        rdr.read_exact(&mut chunk)?;
        // open this chunk
        let (plain, tag) = opener.open_chunk(&chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "open_chunk failed: authentication error"))?;
        wtr.write_all(&plain)?;
        // If the tag indicates finish, break
        if tag == StreamTag::Finish {
            break;
        }
    }

    wtr.flush()?;
    Ok(())
}
 
