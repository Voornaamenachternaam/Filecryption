// main_test.rs

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time;

use argon2::{Algorithm, Argon2, Params, Version};
use clap::{Parser, Subcommand};
use orion::hazardous::aead::xchacha20poly1305::{self, Nonce, SecretKey as OrionSecretKey};
use rand::RngCore;
use rpassword::prompt_password;
use zeroize::Zeroizing;

// Import all functions and constants from the main module
use filecryption::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // ─── Helpers ───────────────────────────────────────────────────────────────

    fn create_temp_dir() -> io::Result<PathBuf> {
        let temp_dir = env::temp_dir();
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = temp_dir.join(format!("filecryption_test_{}", timestamp));
        fs::create_dir(&temp_dir)?;
        Ok(temp_dir)
    }

    fn create_test_file(path: &Path, size: usize) -> io::Result<()> {
        let mut file = File::create(path)?;
        let mut buffer = vec![0u8; size];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut buffer);
        file.write_all(&buffer)?;
        Ok(())
    }

    fn compare_files(path1: &Path, path2: &Path) -> io::Result<bool> {
        let mut file1 = File::open(path1)?;
        let mut file2 = File::open(path2)?;
        let metadata1 = file1.metadata()?;
        let metadata2 = file2.metadata()?;
        if metadata1.len() != metadata2.len() {
            return Ok(false);
        }
        let mut buf1 = [0u8; 1024];
        let mut buf2 = [0u8; 1024];
        loop {
            let n1 = file1.read(&mut buf1)?;
            let n2 = file2.read(&mut buf2)?;
            if n1 != n2 { return Ok(false); }
            if n1 == 0 { break; }
            if buf1[..n1] != buf2[..n2] { return Ok(false); }
        }
        Ok(true)
    }

    fn cleanup_temp_dir(dir: &Path) -> io::Result<()> {
        fs::remove_dir_all(dir)
    }

    // ─── Constants ──────────────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC, b"FCRYPT01");
        assert_eq!(SALT_LEN, 16);
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(PLAINTEXT_CHUNK_SIZE, 64 * 1024);
        assert_eq!(CIPHERTEXT_CHUNK_SIZE, PLAINTEXT_CHUNK_SIZE + TAG_LEN);
        assert_eq!(HEADER_SIZE, (MAGIC.len() + SALT_LEN + NONCE_LEN) as u64);
        assert_eq!(MEMORY_COST, 1 << 16);
        assert_eq!(TIME_COST, 3);
        assert_eq!(PARALLELISM, 1);
    }

    // ─── Key Derivation ─────────────────────────────────────────────────────────

    #[test]
    fn test_derive_key() {
        let pw = Zeroizing::new("test123".to_string());
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);

        let k1 = derive_key(&pw, &salt).unwrap();
        let k2 = derive_key(&pw, &salt).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());

        let mut other_salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut other_salt);
        let k3 = derive_key(&pw, &other_salt).unwrap();
        assert_ne!(k1.as_ref(), k3.as_ref());

        let other_pw = Zeroizing::new("diff456".to_string());
        let k4 = derive_key(&other_pw, &salt).unwrap();
        assert_ne!(k1.as_ref(), k4.as_ref());
    }

    #[test]
    fn test_derive_key_invalid_params() {
        assert!(Params::new(0, TIME_COST, PARALLELISM, Some(32)).is_err());
        assert!(Params::new(MEMORY_COST, 0, PARALLELISM, Some(32)).is_err());
        assert!(Params::new(MEMORY_COST, TIME_COST, 0, Some(32)).is_err());
    }

    // ─── Single File Encryption / Decryption ───────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_file() {
        let td = create_temp_dir().unwrap();
        let src = td.join("data.txt");
        let enc = td.join("data.txt.enc");
        create_test_file(&src, 2048).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        encrypt_file(&src, &pw).unwrap();
        assert!(!src.exists());
        assert!(enc.exists());

        decrypt_file(&enc, &pw).unwrap();
        assert!(src.exists());
        assert!(!enc.exists());

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let td = create_temp_dir().unwrap();
        let src = td.join("empty.txt");
        let enc = td.join("empty.txt.enc");
        File::create(&src).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        encrypt_file(&src, &pw).unwrap();
        decrypt_file(&enc, &pw).unwrap();

        assert_eq!(fs::metadata(&src).unwrap().len(), 0);
        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let td = create_temp_dir().unwrap();
        let src = td.join("big.txt");
        let enc = td.join("big.txt.enc");
        create_test_file(&src, PLAINTEXT_CHUNK_SIZE * 5).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        encrypt_file(&src, &pw).unwrap();
        decrypt_file(&enc, &pw).unwrap();

        assert!(compare_files(&src, &td.join("big.txt")).unwrap());
        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let td = create_temp_dir().unwrap();
        let src = td.join("data.txt");
        let enc = td.join("data.txt.enc");
        create_test_file(&src, 1024).unwrap();

        let good_pw = Zeroizing::new("good".to_string());
        encrypt_file(&src, &good_pw).unwrap();

        let bad_pw = Zeroizing::new("bad".to_string());
        assert!(decrypt_file(&enc, &bad_pw).is_err());
        assert!(enc.exists()); // untouched on failure

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let td = create_temp_dir().unwrap();
        let src = td.join("data.txt");
        let enc = td.join("data.txt.enc");
        create_test_file(&src, 1024).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        encrypt_file(&src, &pw).unwrap();

        // flip a bit in the first ciphertext chunk
        let mut data = fs::read(&enc).unwrap();
        data[HEADER_SIZE as usize + 5] ^= 0x01;
        fs::write(&enc, &data).unwrap();

        assert!(decrypt_file(&enc, &pw).is_err());
        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_decrypt_invalid_magic() {
        let td = create_temp_dir().unwrap();
        let src = td.join("data.txt");
        let enc = td.join("data.txt.enc");
        create_test_file(&src, 1024).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        encrypt_file(&src, &pw).unwrap();

        let mut data = fs::read(&enc).unwrap();
        data[0] ^= 0xFF; // corrupt magic
        fs::write(&enc, &data).unwrap();

        assert!(decrypt_file(&enc, &pw).is_err());
        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_encrypt_output_exists() {
        let td = create_temp_dir().unwrap();
        let src = td.join("data.txt");
        let enc = td.join("data.txt.enc");
        create_test_file(&src, 1024).unwrap();
        File::create(&enc).unwrap(); // pre-create output

        let pw = Zeroizing::new("secret".to_string());
        assert!(encrypt_file(&src, &pw).is_err());
        assert!(src.exists()); // original untouched

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_decrypt_non_encrypted() {
        let td = create_temp_dir().unwrap();
        let plain = td.join("plain.txt");
        create_test_file(&plain, 512).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        assert!(decrypt_file(&plain, &pw).is_ok()); // no-op, not .enc
        assert!(plain.exists());

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_decrypt_file_too_short() {
        let td = create_temp_dir().unwrap();
        let bad = td.join("bad.enc");
        fs::write(&bad, MAGIC).unwrap(); // only magic, no salt/nonce

        let pw = Zeroizing::new("secret".to_string());
        assert!(decrypt_file(&bad, &pw).is_err());

        cleanup_temp_dir(&td).unwrap();
    }

    // ─── Directory Walk ────────────────────────────────────────────────────────

    #[test]
    fn test_walk_dir_encrypt() {
        let td = create_temp_dir().unwrap();
        let sub = td.join("sub");
        fs::create_dir(&sub).unwrap();
        let f1 = td.join("f1.txt");
        let f2 = sub.join("f2.txt");
        create_test_file(&f1, 100).unwrap();
        create_test_file(&f2, 200).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        walk_dir(&td, &pw, true).unwrap();

        assert!(!f1.exists()); assert!(f1.with_extension("txt.enc").exists());
        assert!(!f2.exists()); assert!(f2.with_extension("txt.enc").exists());

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_walk_dir_decrypt() {
        let td = create_temp_dir().unwrap();
        let sub = td.join("sub");
        fs::create_dir(&sub).unwrap();
        let e1 = td.join("f1.txt.enc");
        let e2 = sub.join("f2.txt.enc");
        create_test_file(&e1, 100 + HEADER_SIZE as usize).unwrap();
        create_test_file(&e2, 200 + HEADER_SIZE as usize).unwrap();

        let pw = Zeroizing::new("secret".to_string());
        walk_dir(&td, &pw, false).unwrap();

        assert!(!e1.exists()); assert!(td.join("f1.txt").exists());
        assert!(!e2.exists()); assert!(sub.join("f2.txt").exists());

        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_walk_dir_nonexistent() {
        let td = create_temp_dir().unwrap();
        let fake = td.join("nope");
        let pw = Zeroizing::new("secret".to_string());
        assert!(walk_dir(&fake, &pw, true).is_ok()); // no-op
        cleanup_temp_dir(&td).unwrap();
    }

    // ─── TempFile RAII ────────────────────────────────────────────────────────

    #[test]
    fn test_temp_file_persist() {
        let td = create_temp_dir().unwrap();
        let path = td.join("tmp");
        {
            let tf = TempFile::create(&path).unwrap();
            assert!(path.exists());
            tf.persist();
        }
        assert!(path.exists()); // still there
        cleanup_temp_dir(&td).unwrap();
    }

    #[test]
    fn test_temp_file_cleanup() {
        let td = create_temp_dir().unwrap();
        let path = td.join("tmp");
        {
            let _tf = TempFile::create(&path).unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists()); // auto-deleted
        cleanup_temp_dir(&td).unwrap();
    }

    // ─── CLI Parsing ──────────────────────────────────────────────────────────

    #[test]
    fn test_cli_parsing() {
        use clap::Parser;

        let encrypt = Cli::try_parse_from(&["filecryption", "encrypt", "test.txt"]).unwrap();
        matches!(encrypt.command, Command::Encrypt{file} if file == PathBuf::from("test.txt"));

        let decrypt = Cli::try_parse_from(&["filecryption", "decrypt", "test.txt.enc"]).unwrap();
        matches!(decrypt.command, Command::Decrypt{file} if file == PathBuf::from("test.txt.enc"));

        let enc_dir = Cli::try_parse_from(&["filecryption", "encrypt-dir", "dir"]).unwrap();
        matches!(enc_dir.command, Command::EncryptDir{dir} if dir == PathBuf::from("dir"));

        let dec_dir = Cli::try_parse_from(&["filecryption", "decrypt-dir", "dir"]).unwrap();
        matches!(dec_dir.command, Command::DecryptDir{dir} if dir == PathBuf::from("dir"));
    }
}
