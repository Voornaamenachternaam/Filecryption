/*
     This file is part of Filecryption.

    Filecryption is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    Filecryption is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with Filecryption. If not, see <https://www.gnu.org/licenses/>.
*/

use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, ValueEnum};
use orion::aead::{self, open, seal};
use orion::aead::streaming::{StreamSealer, StreamOpener, StreamTag, ABYTES};
use orion::kdf;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use zeroize::Zeroize;
use std::thread;
use std::time::{self, Duration};

const FILEPARAM: &str = ".parameters.txt";
const SALTSIZE: usize = 24;
const ENCRYPTSUFFIX: &str = "_encrypted";
const CHUNK_SIZE: usize = 1000; // The size of the chunks you wish to split the stream into.
const MIN_MEM_ARGON: u8 = 5;
const DEFAULT_ARGON: u8 = 16;
const MAX_MEM_ARGON: u8 = 50;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Action to perform
    #[clap(value_enum, value_parser)]
    action: Action,

    /// Argon parameter (default should be fit, but can be computed with -t), set exponential for argon, must be between 5 (very low - low CPU devices) and 50 (nearly impossible to compute).
    #[arg(short, long, default_value_t = DEFAULT_ARGON, value_parser = clap::value_parser!(u8).range(i64::from(MIN_MEM_ARGON)..=i64::from(MAX_MEM_ARGON)))]
    argon2: u8,

    /// File(s)/Directories to encrypt/decrypt
    #[arg(value_parser)]
    file: Vec<String>,
    /// Encrypt filename
    #[arg(short, long)]
    filename: bool,
    /// Password input
    #[arg(short, long)]
    password: Option<String>,

    ///Recursive all directories and files
    #[arg(short, long)]
    recursive: bool,

    ///verbose mode
    #[clap(short, long)]
    verbose: bool,
}
impl Drop for Args {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Action {
    Encrypt,
    Decrypt,
    Compute,
}

//
// Abstraction for FS / password / sleep / exit so we can provide deterministic Kani mocks
//

// === Non-Kani (real) implementations ===
#[cfg(not(kani))]
fn read_all(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}
#[cfg(not(kani))]
fn read_to_string(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}
#[cfg(not(kani))]
fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    // mimic create_new(true): fail if exists
    if path.exists() {
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "File exists"))
    } else {
        fs::write(path, data)
    }
}
#[cfg(not(kani))]
fn write_over(path: &Path, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}
#[cfg(not(kani))]
fn remove_file(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}
#[cfg(not(kani))]
fn try_exists(path: &Path) -> io::Result<bool> {
    path.try_exists()
}
#[cfg(not(kani))]
fn read_password_prompt(_prompt: &str) -> io::Result<String> {
    rpassword::read_password().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
}
#[cfg(not(kani))]
fn sleep_secs(s: u64) {
    thread::sleep(Duration::new(s, 0));
}
#[cfg(not(kani))]
fn fatal_exit(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

// === Kani (mocked) implementations ===
#[cfg(kani)]
mod kani_vfs {
    use std::collections::HashMap;
    use std::io;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

    fn store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub fn read(path: &Path) -> io::Result<Vec<u8>> {
        let key = path.to_string_lossy().to_string();
        let map = store().lock().unwrap();
        match map.get(&key) {
            Some(v) => Ok(v.clone()),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    pub fn create_new(path: &Path, data: &[u8]) -> io::Result<()> {
        let key = path.to_string_lossy().to_string();
        let mut map = store().lock().unwrap();
        if map.contains_key(&key) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
        }
        map.insert(key, data.to_vec());
        Ok(())
    }

    pub fn write_over(path: &Path, data: &[u8]) -> io::Result<()> {
        let key = path.to_string_lossy().to_string();
        let mut map = store().lock().unwrap();
        map.insert(key, data.to_vec());
        Ok(())
    }

    pub fn remove(path: &Path) -> io::Result<()> {
        let key = path.to_string_lossy().to_string();
        let mut map = store().lock().unwrap();
        if map.remove(&key).is_some() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "not found"))
        }
    }

    pub fn exists(path: &Path) -> io::Result<bool> {
        let key = path.to_string_lossy().to_string();
        let map = store().lock().unwrap();
        Ok(map.contains_key(&key))
    }

    // Helpers for the Kani harnesses to populate the VFS
    pub fn put(path: &str, data: &[u8]) {
        let mut map = store().lock().unwrap();
        map.insert(path.to_string(), data.to_vec());
    }

    #[allow(dead_code)]
    pub fn list_keys() -> Vec<String> {
        let map = store().lock().unwrap();
        map.keys().cloned().collect()
    }
}

#[cfg(kani)]
fn read_all(path: &Path) -> io::Result<Vec<u8>> {
    kani_vfs::read(path)
}
#[cfg(kani)]
fn read_to_string(path: &Path) -> io::Result<String> {
    kani_vfs::read(path).and_then(|v| {
        String::from_utf8(v).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
    })
}
#[cfg(kani)]
fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    kani_vfs::create_new(path, data)
}
#[cfg(kani)]
fn write_over(path: &Path, data: &[u8]) -> io::Result<()> {
    kani_vfs::write_over(path, data)
}
#[cfg(kani)]
fn remove_file(path: &Path) -> io::Result<()> {
    kani_vfs::remove(path)
}
#[cfg(kani)]
fn try_exists(path: &Path) -> io::Result<bool> {
    kani_vfs::exists(path)
}
#[cfg(kani)]
fn read_password_prompt(_prompt: &str) -> io::Result<String> {
    // deterministic password for verification
    Ok(String::from("kani-test-password"))
}
#[cfg(kani)]
fn sleep_secs(_s: u64) {
    // no-op for verification
}
#[cfg(kani)]
fn fatal_exit(msg: &str) -> ! {
    panic!("{}", msg);
}

//
// End of abstraction helpers
//

fn extractmasterkey(
    encrypt: bool,
    path: &Path,
    argon2: u8,
    password: &Option<String>,
) -> aead::SecretKey {
    #[allow(unused_assignments, unused_mut)]
    let mut salt;
    #[allow(unused_assignments)]
    let mut calc: u8 = 0;
    match read_to_string(path) {
        Ok(buffer) => {
            let buffer: Vec<&str> = buffer.split(':').collect();
            if buffer.len() != 2 {
                fatal_exit("Error on reading parameters");
            }
            calc = buffer[0].trim().parse().expect("Invalid parameters format.");
            if !(MIN_MEM_ARGON..=MAX_MEM_ARGON).contains(&calc) {
                fatal_exit("Invalid identifier");
            }
            salt = kdf::Salt::from_slice(
                &general_purpose::STANDARD
                    .decode(buffer[1].trim())
                    .expect("Error reading salt from parameters."),
            )
            .expect("Error reading salt from parameters.");
        }
        Err(_) => {
            if !encrypt {
                eprintln!("Parameters file cannot be found! Cannot decrypt.");
                fatal_exit("Missing parameters");
            } else {
                salt = kdf::Salt::generate(SALTSIZE).expect("Cannot generate secure salt");
                calc = argon2;
                let text = format!("{}:{}", calc, &general_purpose::STANDARD.encode(&salt));
                if let Err(e) = write_new_file(path, text.as_bytes()) {
                    eprintln!("The error is {:?} for the file {:?}", e, path.file_name());
                    fatal_exit("Cannot create parameters file");
                }
            }
        }
    };
    let mut passwordorion: orion::pwhash::Password;
    match password {
        Some(password) => {
            passwordorion =
                kdf::Password::from_slice(password.as_bytes()).expect("Cannot derive password");
        }
        None => {
            let mut password2;
            let mut password2orion: orion::pwhash::Password;
            let encryptpass = "Enter the master password (don't forget it!):";
            let encryptpass2 = "Confirm the master password (don't forget it!):";
            let decryptpass = "Enter the master password:";
            loop {
                if encrypt {
                    println!("{}", encryptpass);
                } else {
                    println!("{}", decryptpass);
                }
                let password = read_password_prompt(if encrypt {
                    encryptpass
                } else {
                    decryptpass
                })
                .expect("Cannot read password");
                passwordorion = kdf::Password::from_slice(password.as_bytes()).unwrap();
                if encrypt {
                    println!("{}", encryptpass2);
                    password2 = read_password_prompt(encryptpass2).expect("Cannot read password");
                    password2orion = kdf::Password::from_slice(password2.as_bytes()).unwrap();
                    if password2orion == passwordorion {
                        // Constant-time comparison semantics provided by the type
                        break;
                    }
                    // Limit force cracking
                    sleep_secs(3);
                    eprintln!("Passwords are not the same, please retry!");
                } else {
                    break;
                }
            }
        }
    };
    let derived_key =
        kdf::derive_key(&passwordorion, &salt, 3, 1 << calc, 32).unwrap_or_else(|_| {
            fatal_exit("Cannot derive key");
        });
    aead::SecretKey::from_slice(derived_key.unprotected_as_bytes()).unwrap()
}

fn recurse_files(path: impl AsRef<Path>) -> std::io::Result<Vec<PathBuf>> {
    let mut buf = vec![];
    let entries = fs::read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;

        if meta.is_dir() {
            let mut subdir = recurse_files(entry.path())?;
            buf.append(&mut subdir);
        }

        if meta.is_file() {
            buf.push(entry.path());
        }
    }
    Ok(buf)
}

fn getfiles(filepaths: Vec<String>, verbose: bool, recursive: bool) -> (Vec<PathBuf>, String) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut params: String = String::new();
    for file in &filepaths {
        let path = Path::new(&file);
        let result = try_exists(path).expect("Cannot access this file");
        if !result {
            eprintln!("The file {} is not readable.", file);
            fatal_exit("File not readable");
        } else {
            match path.file_name() {
                Some(filecheck) => {
                    if filecheck == OsStr::new(FILEPARAM) {
                        params = String::from(file);
                        continue;
                    }
                }
                None => {
                    eprintln!("The file {} is not readable.", file);
                    fatal_exit("File not readable");
                }
            }
            if path.is_dir() && recursive {
                let dirs = &mut recurse_files(file);
                match dirs {
                    Ok(dir) => {
                        files.append(dir);
                    }
                    Err(err) => {
                        eprintln!("The directory {} has an error: {:?}", file, err);
                    }
                }
            } else if path.is_dir() {
                if verbose {
                    println!(
                        "The directory {} will be skipped in non-recursive mode.",
                        file
                    );
                }
            } else if path.is_file() {
                files.push(PathBuf::from(file));
            }
        }
    }
    if files.is_empty() {
        eprintln!("No files were found!");
        fatal_exit("No files found");
    }
    params = match try_exists(Path::new(&params)) {
        Ok(result) => {
            if result {
                params
            } else {
                String::from(FILEPARAM)
            }
        }
        Err(_) => String::from(FILEPARAM),
    };
    (files, params)
}

fn getparent(path: &Path) -> (String, String) {
    let newfilename = Path::new(path);
    let pathname = newfilename.parent().unwrap_or(newfilename);
    let filenameplain = newfilename.file_name().expect("Cannot detect filename tree");
    (
        String::from(pathname.to_str().unwrap()),
        String::from(filenameplain.to_str().unwrap()),
    )
}

pub fn encryptastream(
    secret_key: &aead::SecretKey,
    files: Vec<PathBuf>,
    verbose: bool,
    filenameencrypt: bool,
) {
    for file in files {
        let filedata: String = match file.to_str() {
            Some(x) => String::from(x),
            None => {
                eprintln!("Cannot get correct filename");
                return;
            }
        };
        if filedata.ends_with(ENCRYPTSUFFIX) {
            if verbose {
                println!("The file {} is already encrypted", filedata);
            }
            continue;
        }

        let (mut sealer, nonce) = StreamSealer::new(secret_key).unwrap();

        let data = read_all(Path::new(&filedata));
        if data.is_err() {
            eprintln!(
                "The error is {} for the file {:?}",
                data.unwrap_err(),
                &filedata
            );
            return;
        }
        let mut data = data.unwrap(); //Cannot be wrong

        let filename = filedata.clone();
        let (pathname, filenameplain) = getparent(Path::new(&filename));
        let pathname = Path::new(&pathname);
        let elemfilename;
        let mut newfilename = Path::new(&filename);
        if filenameencrypt {
            elemfilename = pathname.join(general_purpose::URL_SAFE.encode(seal(
                secret_key,
                filenameplain.as_bytes(),
            )
            .expect("Cannot encrypt filename")));
            newfilename = &elemfilename;
        }
        let mut newfilename = String::from(newfilename.to_str().unwrap());
        newfilename.push_str(ENCRYPTSUFFIX);

        // Build full encrypted buffer: nonce + sealed chunks
        let mut outbuf: Vec<u8> = vec![];
        outbuf.extend_from_slice(nonce.as_ref());

        for (n_chunk, src_chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            let encrypted_chunk =
                if src_chunk.len() != CHUNK_SIZE || n_chunk + 1 == data.len() / CHUNK_SIZE {
                    sealer.seal_chunk(src_chunk, &StreamTag::Finish).unwrap()
                } else {
                    sealer.seal_chunk(src_chunk, &StreamTag::Message).unwrap()
                };
            outbuf.extend_from_slice(&encrypted_chunk);
        }

        // write new encrypted file
        if let Err(e) = write_new_file(Path::new(&newfilename), &outbuf) {
            eprintln!("The error is {} for the file {:?}", e, &newfilename);
            continue;
        }

        // zeroize and empty original file
        data.zeroize();
        let blank: String = String::new();
        if let Err(e) = write_over(Path::new(&filedata), blank.as_bytes()) {
            eprintln!("The error is {} for the file {:?}", e, &filedata);
            continue;
        }
        if let Err(e) = remove_file(Path::new(&filedata)) {
            eprintln!(
                "The error is {} for the file {}. Deletion impossible",
                e, &filedata
            );
            continue;
        }
        if verbose {
            println!("Following file has been encrypted: '{}'.", &filedata);
        }
    }
}

pub fn decryptastream(
    secret_key: &aead::SecretKey,
    files: Vec<PathBuf>,
    verbose: bool,
    filenamencrypt: bool,
) -> bool {
    let mut count: usize = 0;
    let size = files.len();
    for file in files {
        let filedata: String = match file.to_str() {
            Some(x) => String::from(x),
            None => {
                eprintln!("Cannot get correct filename");
                continue;
            }
        };
        if !filedata.ends_with(ENCRYPTSUFFIX) {
            if verbose {
                println!("The file {} is not encrypted, skipped.", file.display())
            }
            continue;
        }

        // read full file
        let all = read_all(Path::new(&filedata));
        if all.is_err() {
            eprintln!(
                "The error is {} for the file {:?}",
                all.unwrap_err(),
                &filedata
            );
            continue;
        }
        let mut all = all.unwrap();
        if all.len() < SALTSIZE {
            eprintln!("Lack characters to decrypt for the file {:?}", &filedata);
            continue;
        }
        let data = all.split_off(SALTSIZE);
        let nonce = orion::hazardous::stream::xchacha20::Nonce::from_slice(&all).unwrap();

        let mut opener = StreamOpener::new(secret_key, &nonce).unwrap();

        let mut filename = filedata.clone();
        filename = String::from(filename.as_str().trim_end_matches(ENCRYPTSUFFIX)); //Remove last _encrypted
        let (pathname, filenameplain) = getparent(Path::new(&filename));
        let pathname = Path::new(&pathname);
        let mut newfilename = Path::new(&filename).to_path_buf();

        // If filenamencrypt is true, attempt to decrypt filename bytes (URL_SAFE decode first)
        if filenamencrypt {
            let binaryfilename = open(
                secret_key,
                &general_purpose::URL_SAFE
                    .decode(filenameplain.as_bytes())
                    .expect("Cannot decrypt filename"),
            );
            if binaryfilename.is_err() {
                eprintln!(
                    "The error is {} for the file {:?}",
                    binaryfilename.unwrap_err(),
                    &filename
                );
                continue;
            }
            newfilename = pathname.join(String::from_utf8(binaryfilename.unwrap()).unwrap());
        }

        // we'll collect decrypted bytes here
        let mut outbuf: Vec<u8> = vec![];
        let decipher_chunk = CHUNK_SIZE + ABYTES;

        let mut error = false;
        for (n_chunk, src_chunk) in data.chunks(decipher_chunk).enumerate() {
            let openerfile = opener.open_chunk(src_chunk);
            if openerfile.is_err() {
                // Remove partially created output file if any
                let _ = remove_file(Path::new(&filename));
                eprintln!(
                    "The error is {} for the file {:?}, probably invalid password. Exiting.",
                    openerfile.unwrap_err(),
                    &filedata
                );
                error = true;
                break;
            }
            let (decrypted_chunk, tag) = openerfile.unwrap();
            // If this chunk is the last chunk we expect Finish tag
            if src_chunk.len() != CHUNK_SIZE + ABYTES || n_chunk + 1 == (data.len() + decipher_chunk - 1) / decipher_chunk {
                assert_eq!(tag, StreamTag::Finish, "Stream has been truncated!");
            }
            outbuf.extend_from_slice(&decrypted_chunk);
        }
        if error {
            break;
        }

        // Write decrypted content into new file (create_new semantics)
        if let Err(e) = write_new_file(&newfilename, &outbuf) {
            eprintln!("The error is {} for the file {:?}", e, &newfilename);
            continue;
        }

        // truncate and remove original encrypted
        let blank: String = String::new();
        if let Err(e) = write_over(Path::new(&filedata), blank.as_bytes()) {
            eprintln!("The error is {} for the file {:?}", e, &filedata);
            continue;
        }
        if let Err(e) = remove_file(Path::new(&filedata)) {
            eprintln!("The error is {} for the file {}", e, &filedata);
            continue;
        }
        if verbose {
            println!("The file {} has been decrypted successfully.", &filedata);
        }
        count += 1;
    }
    if count == 0 {
        eprintln!("Cannot decrypt any files!");
        fatal_exit("No files decrypted");
    }
    count == size
}

fn main() {
    let args = Args::parse();
    let verbose = args.verbose;
    let filenameencrypt = args.filename;
    match args.action {
        Action::Encrypt => {
            let (files, fileparam) = getfiles(args.file.clone(), args.verbose, args.recursive);
            let secret_key =
                extractmasterkey(true, Path::new(&fileparam), args.argon2, &args.password);
            encryptastream(&secret_key, files, verbose, filenameencrypt);
        }
        Action::Decrypt => {
            let (files, fileparam) = getfiles(args.file.clone(), args.verbose, args.recursive);
            let secret_key =
                extractmasterkey(false, Path::new(&fileparam), args.argon2, &args.password);
            let result = decryptastream(&secret_key, files, verbose, filenameencrypt);
            if result {
                match remove_file(Path::new(&fileparam)) {
                    Ok(_) => {}
                    Err(_) => {
                        eprintln!("Cannot delete parameters");
                    }
                }
            } else {
                eprintln!("All files could not be decrypted!");
            }
        }
        Action::Compute => {
            if verbose {
                println!(
                    "Getting parameter to derive the master key, please wait several seconds."
                );
            }
            let mut now = time::Instant::now();
            let user_password = kdf::Password::from_slice(b"This is an attempt").unwrap();
            let salt = kdf::Salt::default();
            for i in MIN_MEM_ARGON..=MAX_MEM_ARGON {
                let _derived_key = kdf::derive_key(&user_password, &salt, 3, 1 << i, 32).unwrap();
                if now.elapsed().as_millis() > 5000 {
                    let base: u32 = 2;
                    let calc = i - 1;
                    if verbose {
                        println!(
                            "The parameter used should be {} which corresponds to {} MiB",
                            calc,
                            (1 << calc) / base.pow(10)
                        );
                    } else {
                        println!("{}", calc);
                    }
                    break;
                } else {
                    now = time::Instant::now();
                }
            }
        }
    }
}

//
// Extended Kani harnesses (only compiled when Kani runs). They exercise roundtrip paths deterministically.
// Added: filename-encryption harness and a compute-like harness plus a decrypt-with-params harness.
//
#[cfg(kani)]
mod kani_tests {
    use super::*;
    use std::path::PathBuf;

    fn put_file(path: &str, data: &[u8]) {
        kani_vfs::put(path, data);
    }

    #[kani::proof]
    fn proof_extract_master_key_create_and_derive() {
        let params_path = Path::new(FILEPARAM);
        let key = extractmasterkey(true, params_path, MIN_MEM_ARGON, &Some(String::from("pw")));
        assert_eq!(key.unprotected_as_bytes().len(), 32usize);
    }

    #[kani::proof]
    fn proof_encrypt_then_decrypt_roundtrip() {
        let fname = "testfile.txt";
        put_file(fname, b"hello kani");
        let params_path = Path::new(FILEPARAM);
        let secret_key = extractmasterkey(true, params_path, MIN_MEM_ARGON, &Some(String::from("pw")));
        encryptastream(&secret_key, vec![PathBuf::from(fname)], false, false);
        let encrypted_name = format!("{}{}", fname, ENCRYPTSUFFIX);
        let result = decryptastream(&secret_key, vec![PathBuf::from(encrypted_name.clone())], false, false);
        assert!(result);
        let _ = read_all(Path::new(fname)).expect("Decrypted file must be present");
    }

    #[kani::proof]
    fn proof_filename_encrypt_then_decrypt_roundtrip() {
        // Put a file in a directory to ensure parent path logic exercised
        let fname = "d/testfile.txt";
        put_file(fname, b"data-for-filename-encrypt");
        let params_path = Path::new(FILEPARAM);
        // make a secret key (create params)
        let secret_key = extractmasterkey(true, params_path, MIN_MEM_ARGON, &Some(String::from("pw")));
        // encrypt with filename encryption enabled
        encryptastream(&secret_key, vec![PathBuf::from(fname)], false, true);
        // compute expected encrypted filename: parent join + URL_SAFE.encode(seal(...)) + suffix
        let (_parent, fname_plain) = getparent(Path::new(fname));
        let encoded = general_purpose::URL_SAFE.encode(seal(&secret_key, fname_plain.as_bytes()).unwrap());
        let encrypted_path = format!("d/{}{}", encoded, ENCRYPTSUFFIX);
        // decrypt telling the function filename bytes are encoded
        let result = decryptastream(&secret_key, vec![PathBuf::from(encrypted_path.clone())], false, true);
        assert!(result);
        // original file should be back in VFS
        let _ = read_all(Path::new(fname)).expect("Decrypted file must be present after filename decrypt");
    }

    #[kani::proof]
    fn proof_compute_like_derive_keys() {
        let user_password = kdf::Password::from_slice(b"compute-test").unwrap();
        let salt = kdf::Salt::default();
        // exercise a small contiguous range of Argon iterations to ensure derive_key succeeds
        for i in MIN_MEM_ARGON..=MIN_MEM_ARGON + 2 {
            let derived_key = kdf::derive_key(&user_password, &salt, 3, 1 << i, 32).unwrap();
            assert_eq!(derived_key.unprotected_as_bytes().len(), 32usize);
        }
    }

    #[kani::proof]
    fn proof_extractmasterkey_decrypt_mode_with_params() {
        // Create deterministic salt bytes and write a parameters file (mimics an existing params file)
        let mut salt_bytes = [0u8; SALTSIZE];
        for i in 0..SALTSIZE {
            salt_bytes[i] = (i as u8).wrapping_add(1);
        }
        let encoded = general_purpose::STANDARD.encode(&salt_bytes);
        let text = format!("{}:{}", MIN_MEM_ARGON, encoded);
        kani_vfs::put(FILEPARAM, text.as_bytes());
        let key = extractmasterkey(false, Path::new(FILEPARAM), MIN_MEM_ARGON, &Some(String::from("pw2")));
        assert_eq!(key.unprotected_as_bytes().len(), 32usize);
    }
}
