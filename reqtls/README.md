#### reqtls是一个轻量的tls库和加/解密库

&nbsp;&nbsp;&nbsp;&nbsp;reqtls是基于boringssl构建，与浏览器行为保持一致

#### 支持：

* tls1.2
* aes_ecb_128
* aes_ecb_192
* aes_ecb_256
* aes_cbc_128
* aes_cbc_192
* aes_cbc_256
* des_ecb
* des_cbc
* base64

#### 加解密示例
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