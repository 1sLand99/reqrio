//! #### reqtls is a lightweight TLS library and encryption/decryption library.
//!
//! &nbsp;&nbsp;&nbsp;&nbsp;reqtls is built on boringssl and maintains consistency with browser behavior.
//!
//! #### Encryption/decryption support：
//!
//! * aes_ecb_128
//! * aes_ecb_192
//! * aes_ecb_256
//! * aes_cbc_128
//! * aes_cbc_192
//! * aes_cbc_256
//! * aes_crt_128
//! * aes_crt_192
//! * aes_crt_256
//! * aes_gcm_192
//! * aes_gcm_256
//! * aes_gcm_128
//! * aes_ofb_192
//! * aes_ofb_256
//! * aes_ofb_128
//! * des_ecb
//! * des_cbc
//! * base64
//! * rsa
//!
//! ### TLS supports TLS 1.2.
//!
//! * aes-gcm-128
//! * aes-gcm-256
//! * chacha20_poly1305
//! * x25519
//! * secp256r1
//! * secp384r1
//! * secp521r1
//!
//! ### Hash support
//!
//! * sha1
//! * sha224
//! * sha256
//! * sha385
//! * sha512
//! * hmac
//!
//! ### Encoding support
//!
//! * base64
//!
//! #### Cipher encryption/decryption examples
//!
//! ```rust
//! fn dd() {
//!     let mut aes = Cipher::des_cbc();
//!     aes.set_secret_key("12345678", Some("12345678"));
//!     let encrypted = aes.encrypt("1234567812345678jhjfhhhhhhhhhhhhhhdhhhhhhhgfdsfdsefdutrythdyrfgytyth8").unwrap();
//!     println!("{:?}", encrypted);
//!     let b64 = base64::b64encode(encrypted).unwrap();
//!     println!("encrypted: {}", b64);
//!
//!     let de_bs = base64::b64decode(b64).unwrap();
//!     println!("decrypted: {:?}", de_bs);
//!     println!("{:?}", aes.decrypt(de_bs).unwrap());
//! }
//! ```
//!
//! ### RsaCipher encryption/decryption example
//!
//! ```rust
//! fn dd() {
//!     let key = RsaKey::gen_new_key(2048).unwrap();
//!     println!("{}", key.to_pri_pem().unwrap());
//!     println!("{}", key.to_pub_pem().unwrap());
//!     println!("{:?}", key.to_pri_der());
//!     println!("{:?}", key.to_pub_der());
//!     let nkey = RsaKey::from_pub_der(key.to_pub_der()).unwrap();
//!     let rsa = RsaCipher::from_key(nkey).unwrap();
//!     let encrypted = rsa.encrypt("adsdfds", true).unwrap();
//!     println!("{} {:?}", encrypted.len(), encrypted);
//!
//!     let nkey = RsaKey::from_pri_der(key.to_pri_der()).unwrap();
//!     let rsa = RsaCipher::from_key(nkey).unwrap();
//!     let decrypted = rsa.decrypt(encrypted.as_slice(), true).unwrap();
//!     println!("{} {:?}", decrypted.len(), decrypted);
//! }
//! ```
//!
//!
pub use connection::Connection;
pub use message::Message;
pub use message::server_hello::ServerHello;
pub use message::client_hello::ClientHello;
pub use message::key_exchange::ClientKeyExchange;
pub use message::certificate::Certificates;
pub use secret::key::PriKey;
pub use record::{RecordLayer, RecordType};
pub use error::RlsError;
pub use version::Version;
pub use range::RangeExt;
pub use boring::{hash, hmac, base64, Cipher, Padding, RsaCipher, RsaKey, SignatureAlgorithm};
pub use hex;
pub use cipher::suite::CipherSuite;
pub use extend::{Extension, ExtensionType, group::GroupType, formats::EcPointFormat, alps::ALPN, SupportVersions};

mod extend;
mod message;
mod prf;
mod cipher;
mod connection;
mod record;
mod version;
mod bytes;
mod secret;
mod error;
pub mod rand;
mod boring;
mod range;
