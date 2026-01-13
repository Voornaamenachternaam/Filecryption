#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use orion::{
    aead::streaming::*,
    aead::SecretKey,
    kdf,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"FCRYPT01";
const CHUNK_SIZE: usize = 64 * 1024;

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
    io::stdout().flush().unwrap();
    let pw = read_password().unwrap();

    if confirm {
        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let confirm_pw = read_password().unwrap();
        if pw != confirm_pw {
            eprintln!("Passwords do not match");
            exit(1);
        }
    }

    Zeroizing::new(pw)
}

fn encrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if path.extension().map_or(false, |e| e == "enc") {
        return Ok(());
    }

    let out_path = path.with_extension(format!(
        "{}.enc",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let input = BufReader::new(File::open(path)?);
    let mut output = BufWriter::new(File::create(&out_path)?);

    output.write_all(MAGIC)?;
    output.write_all(&salt)?;
    output.write_all(&nonce)?;

    let mut enc = StreamEncryptorXChaCha20Poly1305::new(&key, &nonce)?;

    let mut reader = input;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            let tag = enc.finish(&[], &mut output)?;
            output.write_all(&tag)?;
            break;
        }
        let tag = enc.seal_chunk(&buffer[..n], &mut output)?;
        output.write_all(&tag)?;
    }

    output.flush()?;
    Ok(())
}

fn decrypt_file(path: &Path, password: &Zeroizing<String>) -> io::Result<()> {
    if !path.extension().map_or(false, |e| e == "enc") {
        return Ok(());
    }

    let mut input = BufReader::new(File::open(path)?);

    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
    }

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    input.read_exact(&mut salt)?;
    input.read_exact(&mut nonce)?;

    let key = derive_key(password, &salt)?;
    let mut dec = StreamDecryptorXChaCha20Poly1305::new(&key, &nonce)?;

    let out_path = path.with_extension("");

    let mut output = BufWriter::new(File::create(&out_path)?);
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + 16]);

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let plain = dec.open_chunk(&buffer[..n], &mut output)?;
        output.write_all(&plain)?;
        plain.zeroize();
    }

    output.flush()?;
    Ok(())
}

fn walk_encrypt(dir: &Path, pw: &Zeroizing<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_encrypt(&path, pw)?;
        } else {
            encrypt_file(&path, pw)?;
        }
    }
    Ok(())
}

fn walk_decrypt(dir: &Path, pw: &Zeroizing<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_decrypt(&path, pw)?;
        } else {
            decrypt_file(&path, pw)?;
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
        kdf::Params::argon2id(3, 64 * 1024, 1),
    )
    .map_err(|_| io::Error::new(io::ErrorKind::Other, "KDF failed"))?;

    SecretKey::from_slice(&key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "key init failed"))
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

 
