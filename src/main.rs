#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions, read_dir};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use orion::aead::streaming::*;
use orion::aead::SecretKey;
use orion::kdf;
use rpassword::read_password;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

/// Sidecar parameter file
const PARAM_FILE: &str = ".filecryption.params";

/// Encrypted filename suffix
const ENCRYPT_SUFFIX: &str = ".enc";

/// Streaming chunk size
const CHUNK_SIZE: usize = 128 * 1024;

/// Cryptographic parameters (SECURE)
const ARGON_ITERATIONS: u32 = 10;
const ARGON_MEMORY_KIB: u32 = 65_536; // 64 MiB

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file
    Encrypt { file: PathBuf },

    /// Decrypt a file
    Decrypt { file: PathBuf },

    /// Recursively encrypt a directory
    EncryptDir { dir: PathBuf },

    /// Recursively decrypt a directory
    DecryptDir { dir: PathBuf },
}

#[derive(ZeroizeOnDrop)]
struct SecurePassword {
    value: String,
}

impl SecurePassword {
    fn new(value: String) -> Self {
        Self { value }
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Encrypt { file } => {
            let pw = prompt_password(true);
            encrypt_path(&file, &pw)
        }
        Command::Decrypt { file } => {
            let pw = prompt_password(false);
            decrypt_path(&file, &pw)
        }
        Command::EncryptDir { dir } => {
            let pw = prompt_password(true);
            walk_encrypt(&dir, &pw)
        }
        Command::DecryptDir { dir } => {
            let pw = prompt_password(false);
            walk_decrypt(&dir, &pw)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        exit(1);
    }
}

fn prompt_password(confirm: bool) -> SecurePassword {
    println!("Enter password:");
    let mut p1 = read_password().expect("password read failed");

    if confirm {
        println!("Confirm password:");
        let mut p2 = read_password().expect("password read failed");

        if p1 != p2 {
            p1.zeroize();
            p2.zeroize();
            exit_with("Passwords do not match");
        }
        p2.zeroize();
    }

    SecurePassword::new(p1)
}

fn exit_with(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(1);
}

fn encrypt_path(path: &Path, pw: &SecurePassword) -> io::Result<()> {
    if !path.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Not a file"));
    }

    let out = path.with_extension(format!(
        "{}{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        ENCRYPT_SUFFIX
    ));

    let salt = kdf::Salt::default();
    write_params(path, &salt)?;

    let key = derive_key(&pw.value, &salt)?;
    encrypt_stream(path, &out, &key)?;
    Ok(())
}

fn decrypt_path(path: &Path, pw: &SecurePassword) -> io::Result<()> {
    let (salt) = read_params(path)?;
    let key = derive_key(&pw.value, &salt)?;

    let out = path.with_extension("dec");
    decrypt_stream(path, &out, &key)?;
    Ok(())
}

fn derive_key(password: &str, salt: &kdf::Salt) -> io::Result<SecretKey> {
    let pw = kdf::Password::from_slice(password.as_bytes())
        .map_err(|_| io::Error::other("Invalid password"))?;

    kdf::derive_key(
        &pw,
        salt,
        ARGON_ITERATIONS,
        ARGON_MEMORY_KIB,
        32,
    )
    .map_err(|_| io::Error::other("Key derivation failed"))
}

fn encrypt_stream(in_p: &Path, out_p: &Path, key: &SecretKey) -> io::Result<()> {
    let mut rdr = BufReader::new(File::open(in_p)?);
    let mut wtr = BufWriter::new(create_secure(out_p)?);

    let (mut sealer, nonce) = StreamSealer::new(key)
        .map_err(|_| io::Error::other("Sealer init failed"))?;

    wtr.write_all(nonce.as_ref())?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = rdr.read(&mut buf)?;
        let tag = if n == 0 { StreamTag::Finish } else { StreamTag::Message };

        let enc = sealer
            .seal_chunk(&buf[..n], &tag)
            .map_err(|_| io::Error::other("Seal failed"))?;

        wtr.write_all(&(enc.len() as u64).to_be_bytes())?;
        wtr.write_all(&enc)?;

        if tag == StreamTag::Finish {
            break;
        }
    }
    Ok(())
}

fn decrypt_stream(in_p: &Path, out_p: &Path, key: &SecretKey) -> io::Result<()> {
    let mut rdr = BufReader::new(File::open(in_p)?);
    let mut wtr = BufWriter::new(create_secure(out_p)?);

    let mut nonce = [0u8; 24];
    rdr.read_exact(&mut nonce)?;
    let nonce = Nonce::from_slice(&nonce)
        .map_err(|_| io::Error::other("Invalid nonce"))?;

    let mut opener = StreamOpener::new(key, &nonce)
        .map_err(|_| io::Error::other("Opener init failed"))?;

    loop {
        let mut len = [0u8; 8];
        rdr.read_exact(&mut len)?;
        let len = u64::from_be_bytes(len) as usize;

        let mut buf = vec![0u8; len];
        rdr.read_exact(&mut buf)?;

        let (pt, tag) = opener
            .open_chunk(&buf)
            .map_err(|_| io::Error::other("Auth failed"))?;

        wtr.write_all(&pt)?;

        if tag == StreamTag::Finish {
            break;
        }
    }
    Ok(())
}

fn write_params(path: &Path, salt: &kdf::Salt) -> io::Result<()> {
    let p = path.with_file_name(PARAM_FILE);
    let mut f = create_secure(&p)?;
    let s = general_purpose::STANDARD.encode(salt.as_ref());
    writeln!(f, "{}:{}:{}", ARGON_ITERATIONS, ARGON_MEMORY_KIB, s)?;
    Ok(())
}

fn read_params(path: &Path) -> io::Result<kdf::Salt> {
    let p = path.with_file_name(PARAM_FILE);
    let mut s = String::new();
    File::open(p)?.read_to_string(&mut s)?;

    let parts: Vec<_> = s.trim().split(':').collect();
    if parts.len() != 3 {
        return Err(io::Error::other("Invalid param file"));
    }

    let salt = general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|_| io::Error::other("Bad salt"))?;

    kdf::Salt::from_slice(&salt)
        .map_err(|_| io::Error::other("Salt invalid"))
}

fn create_secure(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).truncate(true).write(true);

    #[cfg(unix)]
    o.mode(0o600);

    #[cfg(windows)]
    o.attributes(0x2);

    o.open(path)
}

fn walk_encrypt(dir: &Path, pw: &SecurePassword) -> io::Result<()> {
    for e in read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            walk_encrypt(&p, pw)?;
        } else {
            encrypt_path(&p, pw)?;
        }
    }
    Ok(())
}

fn walk_decrypt(dir: &Path, pw: &SecurePassword) -> io::Result<()> {
    for e in read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            walk_decrypt(&p, pw)?;
        } else if p.extension().and_then(|e| e.to_str()) == Some("enc") {
            decrypt_path(&p, pw)?;
        }
    }
    Ok(())
}
