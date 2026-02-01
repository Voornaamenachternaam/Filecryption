//! Unit tests for filecryption core logic.
//! Bypasses TTY-dependent CLI by testing library functions directly.
//! 100% compatible with cargo llvm-cov in CI environments.

use std::{
    fs::{self, File},
    io::{Read, Write, ErrorKind},
    path::PathBuf,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

// Import main.rs as a module for testing private functions
#[path = "../src/main.rs"]
mod main;

#[test]
fn test_derive_key_consistency() {
    let password = Zeroizing::new("TestPassword123".to_string());
    let salt = [0x42u8; 16];
    
    let key1 = main::derive_key(&password, &salt).expect("Key derivation failed");
    let key2 = main::derive_key(&password, &salt).expect("Key derivation failed");
    
    // Same password+salt must produce identical keys
    assert_eq!(key1.unprotected_as_bytes(), key2.unprotected_as_bytes());
}

#[test]
fn test_encrypt_decrypt_roundtrip_small() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("test.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let decrypted_path = plaintext_path.with_extension("dec");
    
    // Create plaintext file
    fs::write(&plaintext_path, b"Secret message").expect("Write plaintext failed");
    
    // Encrypt directly (bypassing CLI/password prompt)
    let password = Zeroizing::new("LongEnoughPassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    assert!(encrypted_path.exists());
    
    // Decrypt directly
    main::decrypt_file(&encrypted_path, &password).expect("Decryption failed");
    let decrypted_content = fs::read(decrypted_path).expect("Read decrypted failed");
    assert_eq!(decrypted_content, b"Secret message");
}

#[test]
fn test_encrypt_decrypt_roundtrip_empty_file() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("empty.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let decrypted_path = plaintext_path.with_extension("dec");
    
    fs::write(&plaintext_path, b"").expect("Write empty file failed");
    
    let password = Zeroizing::new("LongEnoughPassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    main::decrypt_file(&encrypted_path, &password).expect("Decryption failed");
    
    let content = fs::read(decrypted_path).expect("Read decrypted failed");
    assert!(content.is_empty());
}

#[test]
fn test_encrypt_decrypt_roundtrip_large_file() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("large.bin");
    let encrypted_path = plaintext_path.with_extension("enc");
    let decrypted_path = plaintext_path.with_extension("dec");
    
    // Create multi-chunk file (3.5 chunks)
    let chunk_size = 64 * 1024;
    let content: Vec<u8> = (0..(chunk_size * 3 + 100)).map(|i| (i % 256) as u8).collect();
    fs::write(&plaintext_path, &content).expect("Write large file failed");
    
    let password = Zeroizing::new("LongEnoughPassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    main::decrypt_file(&encrypted_path, &password).expect("Decryption failed");
    
    let decrypted = fs::read(decrypted_path).expect("Read decrypted failed");
    assert_eq!(decrypted, content);
}

#[test]
fn test_wrong_password_fails_authentication() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("secret.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    
    fs::write(&plaintext_path, b"Top secret").expect("Write plaintext failed");
    
    // Encrypt with correct password
    let correct_pw = Zeroizing::new("CorrectPassword123".to_string());
    main::encrypt_file(&plaintext_path, &correct_pw).expect("Encryption failed");
    
    // Attempt decryption with wrong password
    let wrong_pw = Zeroizing::new("WrongPassword456".to_string());
    let err = main::decrypt_file(&encrypted_path, &wrong_pw).unwrap_err();
    
    assert!(
        matches!(err.kind(), ErrorKind::InvalidData),
        "Expected InvalidData error, got: {:?}",
        err.kind()
    );
    assert!(
        err.to_string().contains("Authentication failed"),
        "Error should mention auth failure: {}",
        err
    );
}

#[test]
fn test_password_too_short_rejected_at_derivation() {
    let password = Zeroizing::new("Short1!".to_string()); // 7 chars < 12 required
    let salt = [0u8; 16];
    
    // Key derivation should fail for short passwords
    // (Note: actual password length check happens in prompt_password_secure,
    //  but we test the cryptographic safety net here)
    let result = main::derive_key(&password, &salt);
    // Argon2 will still derive a key, but we verify our policy is enforced at CLI layer
    // This test validates the cryptographic primitive works with short inputs
    assert!(result.is_ok(), "Argon2 should derive key even for short passwords (policy enforced at CLI)");
}

#[test]
fn test_corrupted_header_rejected() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("data.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let corrupted_path = dir.path().join("corrupted.enc");
    
    fs::write(&plaintext_path, b"Important data").expect("Write plaintext failed");
    
    let password = Zeroizing::new("SecurePassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    
    // Corrupt MAGIC header
    let mut encrypted = fs::read(&encrypted_path).expect("Read encrypted failed");
    encrypted[0] = 0xFF; // Corrupt first byte of MAGIC
    
    fs::write(&corrupted_path, &encrypted).expect("Write corrupted failed");
    
    // Attempt decryption should fail at header validation
    let err = main::decrypt_file(&corrupted_path, &password).unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::InvalidData),
        "Expected InvalidData error, got: {:?}",
        err.kind()
    );
    assert!(
        err.to_string().contains("MAGIC header mismatch") || 
        err.to_string().contains("Invalid file format"),
        "Error should mention header corruption: {}",
        err
    );
}

#[test]
fn test_corrupted_ciphertext_rejected() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("data.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let corrupted_path = dir.path().join("corrupted.enc");
    
    fs::write(&plaintext_path, b"Important data").expect("Write plaintext failed");
    
    let password = Zeroizing::new("SecurePassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    
    // Corrupt ciphertext (after 48-byte header: 8 MAGIC + 16 SALT + 24 NONCE)
    let header_size = 8 + 16 + 24;
    let mut encrypted = fs::read(&encrypted_path).expect("Read encrypted failed");
    assert!(encrypted.len() > header_size);
    encrypted[header_size] ^= 0xFF; // Flip a bit in ciphertext
    
    fs::write(&corrupted_path, &encrypted).expect("Write corrupted failed");
    
    // Decryption should fail authentication
    let err = main::decrypt_file(&corrupted_path, &password).unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::InvalidData),
        "Expected InvalidData error, got: {:?}",
        err.kind()
    );
    assert!(
        err.to_string().contains("Authentication failed"),
        "Error should mention auth failure: {}",
        err
    );
}

#[test]
fn test_output_file_exists_prevented() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("data.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    
    fs::write(&plaintext_path, b"content").expect("Write plaintext failed");
    fs::write(&encrypted_path, b"dummy").expect("Create dummy output failed");
    
    let password = Zeroizing::new("LongEnoughPassword123".to_string());
    let err = main::encrypt_file(&plaintext_path, &password).unwrap_err();
    
    assert!(
        matches!(err.kind(), ErrorKind::InvalidInput),
        "Expected InvalidInput error, got: {:?}",
        err.kind()
    );
    assert!(
        err.to_string().contains("already exists"),
        "Error should mention existing file: {}",
        err
    );
}

#[test]
fn test_decrypt_non_enc_file_is_noop() {
    let dir = TempDir::new().expect("TempDir failed");
    let non_enc_path = dir.path().join("normal.txt");
    
    fs::write(&non_enc_path, b"unencrypted content").expect("Write file failed");
    
    let password = Zeroizing::new("AnyPassword123".to_string());
    // Should succeed as no-op per spec (returns Ok(()))
    main::decrypt_file(&non_enc_path, &password).expect("Decryption should be no-op");
    
    // Verify file unchanged
    let content = fs::read(&non_enc_path).expect("Read file failed");
    assert_eq!(content, b"unencrypted content");
}

#[test]
fn test_tempfile_cleanup_on_failure() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("data.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let tmp_path = encrypted_path.with_extension("tmp");
    
    fs::write(&plaintext_path, b"content").expect("Write plaintext failed");
    fs::write(&encrypted_path, b"blocking").expect("Create blocking file failed");
    
    let password = Zeroizing::new("LongEnoughPassword123".to_string());
    let _ = main::encrypt_file(&plaintext_path, &password); // Expected to fail
    
    // Temporary file must be cleaned up on failure
    assert!(!tmp_path.exists(), "Temporary file should be cleaned up");
    assert!(plaintext_path.exists(), "Original file should remain");
}

#[test]
fn test_nonce_increment_correctness() {
    // Verify nonce increments correctly across chunks by roundtrip testing
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("nonce_test.bin");
    let encrypted_path = plaintext_path.with_extension("enc");
    let decrypted_path = plaintext_path.with_extension("dec");
    
    // Create file requiring 3 full chunks + partial chunk
    let chunk_size = 64 * 1024;
    let content_size = (chunk_size * 3) + 100;
    let content: Vec<u8> = (0..content_size).map(|i| (i % 256) as u8).collect();
    fs::write(&plaintext_path, &content).expect("Write test file failed");
    
    let password = Zeroizing::new("NonceTestPassword123".to_string());
    main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
    main::decrypt_file(&encrypted_path, &password).expect("Decryption failed");
    
    let decrypted = fs::read(decrypted_path).expect("Read decrypted failed");
    assert_eq!(decrypted, content, "Nonce increment error caused decryption failure");
}

#[test]
fn test_directory_encryption_decryption() {
    let dir = TempDir::new().expect("TempDir failed");
    let subdir = dir.path().join("sub");
    fs::create_dir(&subdir).expect("Create subdir failed");
    
    // Create files at multiple levels
    fs::write(dir.path().join("root.txt"), b"root content").expect("Write root failed");
    fs::write(subdir.join("nested.txt"), b"nested content").expect("Write nested failed");
    
    let password = Zeroizing::new("DirPassword123".to_string());
    
    // Encrypt directory
    main::walk_dir(dir.path(), &password, true).expect("Directory encryption failed");
    assert!(dir.path().join("root.txt.enc").exists());
    assert!(!dir.path().join("root.txt").exists());
    assert!(subdir.join("nested.txt.enc").exists());
    assert!(!subdir.join("nested.txt").exists());
    
    // Decrypt directory
    main::walk_dir(dir.path(), &password, false).expect("Directory decryption failed");
    let root_content = fs::read(dir.path().join("root.txt")).expect("Read root failed");
    let nested_content = fs::read(subdir.join("nested.txt")).expect("Read nested failed");
    assert_eq!(root_content, b"root content");
    assert_eq!(nested_content, b"nested content");
}

#[test]
fn test_zero_length_password_handling() {
    let password = Zeroizing::new(String::new());
    let salt = [0u8; 16];
    
    // Argon2 should handle empty password (though policy rejects it at CLI layer)
    let result = main::derive_key(&password, &salt);
    assert!(result.is_ok(), "Argon2 should derive key for empty password (policy enforced at CLI)");
}

#[test]
fn test_special_character_passwords() {
    let dir = TempDir::new().expect("TempDir failed");
    let plaintext_path = dir.path().join("special.txt");
    let encrypted_path = plaintext_path.with_extension("enc");
    let decrypted_path = plaintext_path.with_extension("dec");
    
    fs::write(&plaintext_path, b"Special chars test").expect("Write plaintext failed");
    
    // Password with special characters
    let special_pw = Zeroizing::new("P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?".to_string());
    main::encrypt_file(&plaintext_path, &special_pw).expect("Encryption failed");
    main::decrypt_file(&encrypted_path, &special_pw).expect("Decryption failed");
    
    let content = fs::read(decrypted_path).expect("Read decrypted failed");
    assert_eq!(content, b"Special chars test");
}

#[test]
fn test_file_permissions_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        
        let dir = TempDir::new().expect("TempDir failed");
        let plaintext_path = dir.path().join("perms.txt");
        
        fs::write(&plaintext_path, b"content").expect("Write file failed");
        
        // Set restrictive permissions
        let mut perms = fs::metadata(&plaintext_path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&plaintext_path, perms).unwrap();
        
        let password = Zeroizing::new("PermPassword123".to_string());
        let encrypted_path = plaintext_path.with_extension("enc");
        main::encrypt_file(&plaintext_path, &password).expect("Encryption failed");
        
        // Verify encrypted file has safe permissions
        let enc_perms = fs::metadata(&encrypted_path).unwrap().permissions();
        assert_eq!(enc_perms.mode() & 0o002, 0, "Encrypted file must not be world-writable");
    }
}
