// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//     2fa -add [-7] [-8] [-hotp] name
//     2fa -list
//     2fa [-clip] name
//
// "2fa -add name" adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// "2fa -list" lists the names of all the keys in the keychain.
//
// "2fa name" prints a two-factor authentication code from the key with the
// given name. If "-clip" is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.

use clap::Parser;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;

type HmacSha1 = Hmac<Sha1>;

const COUNTER_LEN: usize = 20;

#[derive(Parser)]
#[command(name = "2fa", about = "two-factor authentication agent")]
struct Cli {
    /// Add a key
    #[arg(long = "add")]
    add: bool,

    /// List keys
    #[arg(long = "list")]
    list: bool,

    /// Add key as HOTP (counter-based) key
    #[arg(long = "hotp")]
    hotp: bool,

    /// Generate 7-digit code
    #[arg(short = '7')]
    seven: bool,

    /// Generate 8-digit code
    #[arg(short = '8')]
    eight: bool,

    /// Copy code to the clipboard
    #[arg(long = "clip")]
    clip: bool,

    /// Key name
    name: Option<String>,
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("\t2fa -add [-7] [-8] [-hotp] keyname");
    eprintln!("\t2fa -list");
    eprintln!("\t2fa [-clip] keyname");
    process::exit(2);
}

fn main() {
    let cli = Cli::parse();

    let home = std::env::var("HOME").unwrap_or_else(|_| {
        log_fatal("HOME environment variable not set");
    });
    let file = PathBuf::from(home).join(".2fa");
    let mut k = read_keychain(&file);

    if cli.list {
        if cli.name.is_some() {
            usage();
        }
        k.list();
        return;
    }
    if cli.name.is_none() && !cli.add {
        if cli.clip {
            usage();
        }
        k.show_all();
        return;
    }
    let name = match &cli.name {
        Some(n) => n.clone(),
        None => usage(),
    };
    if name.chars().any(|c| c.is_whitespace()) {
        log_fatal("name must not contain spaces");
    }
    if cli.add {
        if cli.clip {
            usage();
        }
        k.add(&name, cli.seven, cli.eight, cli.hotp);
        return;
    }
    k.show(&name, cli.clip);
}

fn log_fatal(msg: &str) -> ! {
    eprintln!("2fa: {}", msg);
    process::exit(1);
}

struct Key {
    raw: Vec<u8>,
    digits: usize,
    offset: usize, // offset of counter in file data
}

struct Keychain {
    file: PathBuf,
    data: Vec<u8>,
    keys: BTreeMap<String, Key>,
}

fn read_keychain(file: &PathBuf) -> Keychain {
    let mut c = Keychain {
        file: file.clone(),
        data: Vec::new(),
        keys: BTreeMap::new(),
    };

    let data = match fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                return c;
            }
            log_fatal(&format!("{}", e));
        }
    };
    c.data = data;

    let lines: Vec<&[u8]> = c.data.split(|&b| b == b'\n').collect();
    let mut offset: usize = 0;
    for (i, line) in lines.iter().enumerate() {
        let lineno = i + 1;
        let line_with_newline_len = if i < lines.len() - 1 {
            line.len() + 1 // account for the '\n' delimiter
        } else {
            line.len()
        };
        offset += line_with_newline_len;

        let trimmed = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };

        if trimmed.is_empty() {
            continue;
        }

        let fields: Vec<&[u8]> = trimmed.split(|&b| b == b' ').collect();
        if fields.len() >= 3
            && fields[1].len() == 1
            && fields[1][0] >= b'6'
            && fields[1][0] <= b'8'
        {
            let name = String::from_utf8_lossy(fields[0]).to_string();
            let digits = (fields[1][0] - b'0') as usize;
            let key_str = String::from_utf8_lossy(fields[2]).to_string();

            if let Ok(raw) = decode_key(&key_str) {
                if fields.len() == 3 {
                    c.keys.insert(
                        name,
                        Key {
                            raw,
                            digits,
                            offset: 0,
                        },
                    );
                    continue;
                }
                if fields.len() == 4 && fields[3].len() == COUNTER_LEN {
                    let counter_str = String::from_utf8_lossy(fields[3]).to_string();
                    if counter_str.parse::<u64>().is_ok() {
                        // Valid counter.
                        let mut counter_offset = offset - COUNTER_LEN;
                        if i < lines.len() - 1 {
                            // line had a newline at the end
                            counter_offset -= 1;
                        }
                        c.keys.insert(
                            name,
                            Key {
                                raw,
                                digits,
                                offset: counter_offset,
                            },
                        );
                        continue;
                    }
                }
            }
        }
        eprintln!("2fa: {}:{}: malformed key", file.display(), lineno);
    }
    c
}

impl Keychain {
    fn list(&self) {
        // BTreeMap is already sorted
        for name in self.keys.keys() {
            println!("{}", name);
        }
    }

    fn add(&self, name: &str, flag7: bool, flag8: bool, flag_hotp: bool) {
        let size = if flag7 {
            if flag8 {
                log_fatal("cannot use -7 and -8 together");
            }
            7
        } else if flag8 {
            8
        } else {
            6
        };

        eprint!("2fa key for {}: ", name);
        let mut text = String::new();
        io::stdin()
            .lock()
            .read_line(&mut text)
            .unwrap_or_else(|e| log_fatal(&format!("error reading key: {}", e)));

        // Remove all whitespace
        text = text.chars().filter(|c| !c.is_whitespace()).collect();

        // Pad to multiple of 8 with '='
        let pad = (8 - (text.len() % 8)) % 8;
        text.push_str(&"=".repeat(pad));

        if decode_key(&text).is_err() {
            log_fatal("invalid key");
        }

        let mut line = format!("{} {} {}", name, size, text);
        if flag_hotp {
            line.push(' ');
            line.push_str(&"0".repeat(20));
        }
        line.push('\n');

        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&self.file)
            .unwrap_or_else(|e| log_fatal(&format!("opening keychain: {}", e)));

        // Set file permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }

        f.write_all(line.as_bytes())
            .unwrap_or_else(|e| log_fatal(&format!("adding key: {}", e)));
    }

    fn code(&self, name: &str) -> String {
        let k = match self.keys.get(name) {
            Some(k) => k,
            None => log_fatal(&format!("no such key {:?}", name)),
        };

        let code: u32;
        if k.offset != 0 {
            let counter_bytes = &self.data[k.offset..k.offset + COUNTER_LEN];
            let counter_str = String::from_utf8_lossy(counter_bytes).to_string();
            let n: u64 = counter_str.parse().unwrap_or_else(|_| {
                log_fatal(&format!(
                    "malformed key counter for {:?} ({:?})",
                    name, counter_str
                ))
            });
            let n = n + 1;
            code = hotp(&k.raw, n, k.digits);

            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.file)
                .unwrap_or_else(|e| log_fatal(&format!("opening keychain: {}", e)));

            f.seek(SeekFrom::Start(k.offset as u64))
                .unwrap_or_else(|e| log_fatal(&format!("updating keychain: {}", e)));
            write!(f, "{:0>width$}", n, width = COUNTER_LEN)
                .unwrap_or_else(|e| log_fatal(&format!("updating keychain: {}", e)));
        } else {
            // Time-based key.
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            code = totp(&k.raw, now.as_secs(), k.digits);
        }
        format!("{:0>width$}", code, width = k.digits)
    }

    fn show(&self, name: &str, clip: bool) {
        let code = self.code(name);
        if clip {
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                let _ = clipboard.set_text(&code);
            }
        }
        println!("{}", code);
    }

    fn show_all(&mut self) {
        let mut max = 0usize;
        for k in self.keys.values() {
            if max < k.digits {
                max = k.digits;
            }
        }
        // BTreeMap keys are already sorted
        let names: Vec<String> = self.keys.keys().cloned().collect();
        for name in &names {
            let k = self.keys.get(name).unwrap();
            let code = if k.offset == 0 {
                self.code(name)
            } else {
                "-".repeat(k.digits)
            };
            println!("{:<width$}\t{}", code, name, width = max);
        }
    }
}

fn decode_key(key: &str) -> Result<Vec<u8>, data_encoding::DecodeError> {
    BASE32.decode(key.to_uppercase().as_bytes())
}

fn hotp(key: &[u8], counter: u64, digits: usize) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let offset = (sum[sum.len() - 1] & 0x0F) as usize;
    let v = u32::from_be_bytes([
        sum[offset] & 0x7F,
        sum[offset + 1],
        sum[offset + 2],
        sum[offset + 3],
    ]);
    let mut d: u32 = 1;
    for _ in 0..digits.min(8) {
        d *= 10;
    }
    v % d
}

fn totp(key: &[u8], unix_seconds: u64, digits: usize) -> u32 {
    hotp(key, unix_seconds / 30, digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_key() {
        // "JBSWY3DPEHPK3PXP" is a valid base32 string
        let result = decode_key("JBSWY3DPEHPK3PXP");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 10);
    }

    #[test]
    fn test_decode_key_lowercase() {
        // Case-insensitive decoding should produce same result
        let upper = decode_key("JBSWY3DPEHPK3PXP").unwrap();
        let lower = decode_key("jbswy3dpehpk3pxp").unwrap();
        assert_eq!(upper, lower);
    }

    #[test]
    fn test_decode_key_invalid() {
        let result = decode_key("1"); // '1' is not valid base32
        assert!(result.is_err());
    }

    #[test]
    fn test_hotp() {
        // RFC 4226 test vectors
        // Secret: "12345678901234567890" (ASCII)
        let key = b"12345678901234567890";
        let expected: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (i, &exp) in expected.iter().enumerate() {
            let result = hotp(key, i as u64, 6);
            assert_eq!(result, exp, "HOTP mismatch at counter={}", i);
        }
    }

    #[test]
    fn test_hotp_digits() {
        let key = b"12345678901234567890";
        // 7-digit and 8-digit codes
        let code6 = hotp(key, 0, 6);
        let code7 = hotp(key, 0, 7);
        let code8 = hotp(key, 0, 8);
        assert!(code6 < 1_000_000);
        assert!(code7 < 10_000_000);
        assert!(code8 < 100_000_000);
    }

    #[test]
    fn test_totp() {
        let key = b"12345678901234567890";
        // TOTP at time 0 should equal HOTP at counter 0
        let totp_code = totp(key, 0, 6);
        let hotp_code = hotp(key, 0, 6);
        assert_eq!(totp_code, hotp_code);

        // TOTP at time 59 should still be counter 1 (59/30 = 1)
        let totp_code = totp(key, 59, 6);
        let hotp_code = hotp(key, 1, 6);
        assert_eq!(totp_code, hotp_code);
    }

    #[test]
    fn test_read_keychain_empty_file() {
        let dir = std::env::temp_dir().join("test_2fa_empty");
        let _ = fs::remove_file(&dir);
        fs::write(&dir, "").unwrap();
        let kc = read_keychain(&dir);
        assert!(kc.keys.is_empty());
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn test_read_keychain_totp_key() {
        let dir = std::env::temp_dir().join("test_2fa_totp");
        let _ = fs::remove_file(&dir);
        // JBSWY3DPEHPK3PXP is a valid base32 key
        fs::write(&dir, "github 6 JBSWY3DPEHPK3PXP\n").unwrap();
        let kc = read_keychain(&dir);
        assert!(kc.keys.contains_key("github"));
        let k = kc.keys.get("github").unwrap();
        assert_eq!(k.digits, 6);
        assert_eq!(k.offset, 0); // TOTP key, no counter
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn test_read_keychain_hotp_key() {
        let dir = std::env::temp_dir().join("test_2fa_hotp");
        let _ = fs::remove_file(&dir);
        let content = format!("mykey 6 JBSWY3DPEHPK3PXP {}\n", "0".repeat(COUNTER_LEN));
        fs::write(&dir, &content).unwrap();
        let kc = read_keychain(&dir);
        assert!(kc.keys.contains_key("mykey"));
        let k = kc.keys.get("mykey").unwrap();
        assert_eq!(k.digits, 6);
        assert_ne!(k.offset, 0); // HOTP key, has counter
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn test_read_keychain_nonexistent() {
        let dir = std::env::temp_dir().join("test_2fa_nonexistent_xyz");
        let _ = fs::remove_file(&dir);
        let kc = read_keychain(&dir);
        assert!(kc.keys.is_empty());
    }

    #[test]
    fn test_keychain_list() {
        let dir = std::env::temp_dir().join("test_2fa_list");
        let _ = fs::remove_file(&dir);
        fs::write(
            &dir,
            "alice 6 JBSWY3DPEHPK3PXP\nbob 6 JBSWY3DPEHPK3PXP\n",
        )
        .unwrap();
        let kc = read_keychain(&dir);
        let names: Vec<&String> = kc.keys.keys().collect();
        assert_eq!(names, vec!["alice", "bob"]);
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn test_code_format() {
        // Verify code is zero-padded to correct width
        let dir = std::env::temp_dir().join("test_2fa_code_fmt");
        let _ = fs::remove_file(&dir);
        fs::write(&dir, "test 6 JBSWY3DPEHPK3PXP\n").unwrap();
        let kc = read_keychain(&dir);
        let code = kc.code("test");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let _ = fs::remove_file(&dir);
    }
}
