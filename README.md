[![License](https://img.shields.io/github/license/DorianCoding/filecryption)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Github stars](https://img.shields.io/github/stars/DorianCoding/filecryption
)](https://github.com/DorianCoding/filecryption/stargazers)
[![Language](https://img.shields.io/badge/RUST-red)](https://github.com/rust-lang/rust)
# Filecryption
Allows encryption and decryption of files using Argon2i and XChaCha20Poly1305 in Rust.
## Usage
* Clone the repo, and download the binary for your architecture or run `binary.sh` or `cargo run`. **Rust needs to be installed** (version >= 1.73). If you have a older version, you can try to run it using `cargo run --ignore-rust-version` but it is not guaranteed to work.
* The script works only from the command line.
* Enjoy :+1:
```

File encryption/decryption tool using Argon2 and XChaCha20Poly1305

Usage: filecryption <COMMAND>

Commands:
  encrypt      Encrypt a file (writes <filename>_encrypted)
  decrypt      Decrypt a file produced by this tool
  encrypt-dir  Recursively encrypt all files in a directory (non-hidden)
  decrypt-dir  Recursively decrypt a directory produced by EncryptDir
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

```


> [!IMPORTANT]
> Do not try to reencrypt already encrypted files.
> It is clear that this program performs a real encryption and if you alter, edit encrypted files, the parameters file created or lose your password, it ***will be impossible to decrypt your data***. You should keep a backup on a secure device.
> Do not attempt to change extension, filenames of files, move or delete the parameters file created. However, you can tag it as immuable : `# chattr +i file` (as a root) 


Example :
* `filecryption encrypt file.txt` to encrypt file.txt
* `filecryption decrypt file.txt_encrypted` to decrypt file.txt_encrypted
* `filecryption encrypt-dir ~/documents` to recursively encrypt all files in ~/documents
* `filecryption decrypt-dir ~/documents` to recursively decrypt all files in ~/documents
* `filecryption --help` to show help information

## Informations

Files inside directories won't be taken into account unless recursive is set. 
Password would be asked in secure tty but can be unsecurely provide as an argument.
A hidden file is created containing the salt and derivation parameters for Argon2.
It should be automatically detected when encrypting and decrypting. **This file is needed to decrypt and should not be moved or altered**.

## LICENSE
This program is under GPL-3 licence. 
<img src="/assets/images/gpl-v3-logo.svg" width="300" />
> This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
> This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
> You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

## Argon2i infos

Depending on your platform and devices, [argon parameters](https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-inputs-and-outputs) can be edited. To detect the trade-off configuration, run `./script compute`
and provide this value as `-a value` when using this script. The default value is 16 and is [the recommended value](https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice). 

<details>
  <summary>Table of values for argon parameter and memory cost</summary>

*Keep in mind that values higher than 20 could just make your computer lag or crashes
and you **should really** compute before choosing a higher value than default.*
| Value of argon | Memory cost |
| --- | --- |
| 5 | 32 KB |
| 6 | 64 KB |
| 7 | 128 KB |
| 8 | 256 KB |
| 9 | 512 KB |
| 10 | 1.02 MB |
| 11 | 2.05 MB |
| 12 | 4.1 MB |
| 13 | 8.19 MB |
| 14 | 16.4 MB |
| 15 | 32.8 MB |
| Recommended --> 16 | 65.5 MB |
| 17 | 131 MB |
| 18 | 262 MB |
| 19 | 524 MB |
| 20 | 1.05 GB |
| 21 | 2.1 GB |
| 22 | 4.19 GB |
| 23 | 8.39 GB |
| 24 | 16.8 GB |
| 25 | 33.6 GB |
| 26 | 67.1 GB |
| 27 | 134 GB |
| 28 | 268 GB |
| 29 | 537 GB |
| 30 | 1.07 TB |
| 31 | 2.15 TB |
| 32 | 4.29 TB |
| 33 | 8.59 TB |
| 34 | 17.2 TB |
| 35 | 34.4 TB |
| 36 | 68.7 TB |
| 37 | 137 TB |
| 38 | 275 TB |
| 39 | 550 TB |
| 40 | 1.1 PB |
| 41 | 2.2 PB |
| 42 | 4.4 PB |
| 43 | 8.8 PB |
| 44 | 17.6 PB |
| 45 | 35.2 PB |
| 46 | 70.4 PB |
| 47 | 141 PB |
| 48 | 281 PB |
| 49 | 563 PB |
| 50 | 1.13 EB |

</details>
