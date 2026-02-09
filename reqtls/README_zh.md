#### reqtls是一个轻量的tls库和加/解密库

&nbsp;&nbsp;&nbsp;&nbsp;reqtls是基于boringssl构建，与浏览器行为保持一致

#### 加解密支持：

* aes_ecb_128
* aes_ecb_192
* aes_ecb_256
* aes_cbc_128
* aes_cbc_192
* aes_cbc_256
* aes_crt_128
* aes_crt_192
* aes_crt_256
* aes_gcm_192
* aes_gcm_256
* aes_gcm_128
* aes_ofb_192
* aes_ofb_256
* aes_ofb_128
* des_ecb
* des_cbc
* rsa

#### tls支持tls1.2

* aes-gcm-128
* aes-gcm-256
* chacha20_poly1305
* x25519
* secp256r1
* secp384r1
* secp521r1

#### 密码算法
* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
*
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

* TLS_RSA_WITH_AES_128_GCM_SHA256
* TLS_RSA_WITH_AES_256_GCM_SHA384


#### 签名算法

* RSA_PSS_RSAE_SHA256
* RSA_PSS_RSAE_SHA384
* RSA_PSS_RSAE_SHA512
* ECDSA_SECP256R1_SHA256
* ECDSA_SECP384R1_SHA384
* ECDSA_SECP521R1_SHA512
* RSA_PKCS1_SHA256
* RSA_PKCS1_SHA384
* RSA_PKCS1_SHA512

#### 哈希支持

* sha1
* sha224
* sha256
* sha385
* sha512
* hmac

#### 编码支持

* base64

#### Cipher 加解密示例

```rust
fn dd() {
    let mut aes = Cipher::des_cbc();
    aes.set_secret_key("12345678", Some("12345678"));
    let encrypted = aes.encrypt("1234567812345678jhjfhhhhhhhhhhhhhhdhhhhhhhgfdsfdsefdutrythdyrfgytyth8").unwrap();
    println!("{:?}", encrypted);
    let b64 = base64::b64encode(encrypted).unwrap();
    println!("encrypted: {}", b64);

    let de_bs = base64::b64decode(b64).unwrap();
    println!("decrypted: {:?}", de_bs);
    println!("{:?}", aes.decrypt(de_bs).unwrap());
}
```

#### RsaCipher 加解密示例

```rust
fn dd() {
    let key = RsaKey::gen_new_key(2048).unwrap();
    println!("{}", key.to_pri_pem().unwrap());
    println!("{}", key.to_pub_pem().unwrap());
    println!("{:?}", key.to_pri_der());
    println!("{:?}", key.to_pub_der());
    let nkey = RsaKey::from_pub_der(key.to_pub_der()).unwrap();
    let rsa = RsaCipher::from_key(nkey).unwrap();
    let encrypted = rsa.encrypt("adsdfds", true).unwrap();
    println!("{} {:?}", encrypted.len(), encrypted);

    let nkey = RsaKey::from_pri_der(key.to_pri_der()).unwrap();
    let rsa = RsaCipher::from_key(nkey).unwrap();
    let decrypted = rsa.decrypt(encrypted.as_slice(), true).unwrap();
    println!("{} {:?}", decrypted.len(), decrypted);
}
```

#### 证书读取示例
```rust
fn dd() {
    //读取证书链
    let certificates = Certificate::from_pem_file(pem)?;
    //读取证书私钥
    let certificate_key = RsaKey::from_pri_pem_file(key)?;
}
```

#### 哈希计算示例
```rust
fn dd(){
    let mut hash = Hasher::new(Sha::Sha256).unwrap();
    hash.update("fd").unwrap();
    let bs = hash.current_hash().unwrap();
    let bs = hash.finalize().unwrap();

    let bs = hash::sha256("fd").unwrap();

    let mut hmac = Hmac::new("key", Sha::Sha256).unwrap();
    hmac.update("fs").unwrap();
    let bs=hmac.finalize().unwrap();
}
```