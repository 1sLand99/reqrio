use std::fmt::{Debug, Formatter};
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use std::ptr::null_mut;
use crate::boring::ffi::CPointer;

#[derive(PartialEq)]
pub struct SignatureAlgorithm(u16);

impl SignatureAlgorithm {
    pub fn new(v: u16) -> SignatureAlgorithm { SignatureAlgorithm(v) }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 { self.0 }

    fn evp_md(&self) -> *const EVP_MD {
        match *self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => unsafe { EVP_sha256() }
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => unsafe { EVP_sha512() }
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => unsafe { EVP_sha256() }
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => unsafe { EVP_sha512() }
            SignatureAlgorithm::RSA_PKCS1_SHA1 => unsafe { EVP_sha1() }
            SignatureAlgorithm::RSA_PKCS1_SHA256 => unsafe { EVP_sha256() },
            SignatureAlgorithm::RSA_PKCS1_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::RSA_PKCS1_SHA512 => unsafe { EVP_sha512() }
            _ => panic!("unsupported signature algorithm"),
        }
    }

    fn padding(&self) -> i32 {
        match *self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA256 => RSA_PKCS1_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA384 => RSA_PKCS1_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA512 => RSA_PKCS1_PADDING,
            _ => panic!("unsupported signature algorithm"),
        }
    }

    fn is_rsa(&self) -> bool {
        self.spec().to_lowercase().starts_with("rsa")
    }


    fn salt_len(&self) -> i32 {
        match *self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => 32,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => 48,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => 64,
            _ => panic!("unsupported signature algorithm"),
        }
    }
}

impl SignatureAlgorithm {
    pub const RSA_PKCS1_SHA1: SignatureAlgorithm = SignatureAlgorithm(0x0201);
    pub const RSA_PKCS1_SHA256: SignatureAlgorithm = SignatureAlgorithm(0x0401);
    pub const RSA_PKCS1_SHA384: SignatureAlgorithm = SignatureAlgorithm(0x0501);
    pub const RSA_PKCS1_SHA512: SignatureAlgorithm = SignatureAlgorithm(0x0601);
    pub const RSA_PSS_RSAE_SHA256: SignatureAlgorithm = SignatureAlgorithm(0x0804);
    pub const RSA_PSS_RSAE_SHA384: SignatureAlgorithm = SignatureAlgorithm(0x0805);
    pub const RSA_PSS_RSAE_SHA512: SignatureAlgorithm = SignatureAlgorithm(0x0806);
    pub const RSA_PSS_PSS_SHA256: SignatureAlgorithm = SignatureAlgorithm(0x0807);
    pub const RSA_PSS_PSS_SHA384: SignatureAlgorithm = SignatureAlgorithm(0x0808);
    pub const RSA_PSS_PSS_SHA512: SignatureAlgorithm = SignatureAlgorithm(0x0809);
    pub const ED25519: SignatureAlgorithm = SignatureAlgorithm(0x080A);
    pub const ED448: SignatureAlgorithm = SignatureAlgorithm(0x080B);
    pub const ECDSA_SHA1: SignatureAlgorithm = SignatureAlgorithm(0x0203);
    pub const ECDSA_SECP256R1_SHA256: SignatureAlgorithm = SignatureAlgorithm(0x0403);
    pub const ECDSA_SECP384R1_SHA384: SignatureAlgorithm = SignatureAlgorithm(0x0503);
    pub const ECDSA_SECP521R1_SHA512: SignatureAlgorithm = SignatureAlgorithm(0x0603);
    pub const SHA1_DSA: SignatureAlgorithm = SignatureAlgorithm(0x0202);
    pub const SHA224_RSA: SignatureAlgorithm = SignatureAlgorithm(0x0301);
    pub const SHA224_DSA: SignatureAlgorithm = SignatureAlgorithm(0x0302);
    pub const SHA224_ECDSA: SignatureAlgorithm = SignatureAlgorithm(0x0303);
    pub const SHA256_DSA: SignatureAlgorithm = SignatureAlgorithm(0x0402);
    pub const SHA384_DSA: SignatureAlgorithm = SignatureAlgorithm(0x0502);
    pub const SHA512_DSA: SignatureAlgorithm = SignatureAlgorithm(0x0602);

    pub const ALL: [u16; 23] = [0x0201, 0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0203, 0x0403, 0x0503, 0x0603, 0x0202, 0x0301, 0x0302, 0x0303, 0x0402, 0x0502, 0x0602];
    pub fn spec(&self) -> &'static str {
        match *self {
            SignatureAlgorithm::RSA_PKCS1_SHA1 => "RSA_PKCS1_SHA1",
            SignatureAlgorithm::RSA_PKCS1_SHA256 => "RSA_PKCS1_SHA256",
            SignatureAlgorithm::RSA_PKCS1_SHA384 => "RSA_PKCS1_SHA384",
            SignatureAlgorithm::RSA_PKCS1_SHA512 => "RSA_PKCS1_SHA512",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => "RSA_PSS_RSAE_SHA256",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => "RSA_PSS_RSAE_SHA384",
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => "RSA_PSS_RSAE_SHA512",
            SignatureAlgorithm::RSA_PSS_PSS_SHA256 => "RSA_PSS_PSS_SHA256",
            SignatureAlgorithm::RSA_PSS_PSS_SHA384 => "RSA_PSS_PSS_SHA384",
            SignatureAlgorithm::RSA_PSS_PSS_SHA512 => "RSA_PSS_PSS_SHA512",
            SignatureAlgorithm::ED25519 => "ED25519",
            SignatureAlgorithm::ED448 => "ED448",
            SignatureAlgorithm::ECDSA_SHA1 => "ECDSA_SHA1",
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => "ECDSA_SECP256R1_SHA256",
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => "ECDSA_SECP384R1_SHA384",
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => "ECDSA_SECP521R1_SHA512",
            SignatureAlgorithm::SHA1_DSA => "SHA1_DSA",
            SignatureAlgorithm::SHA224_RSA => "SHA224_RSA",
            SignatureAlgorithm::SHA224_DSA => "SHA224_DSA",
            SignatureAlgorithm::SHA224_ECDSA => "SHA224_ECDSA",
            SignatureAlgorithm::SHA256_DSA => "SHA256_DSA",
            SignatureAlgorithm::SHA384_DSA => "SHA384_DSA",
            SignatureAlgorithm::SHA512_DSA => "SHA512_DSA",
            _ => "Reserved"
        }
    }
}

impl Debug for SignatureAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

pub struct AlgorithmSigner {
    md_ctx: CPointer<EVP_MD_CTX>,
}

impl AlgorithmSigner {
    fn init_ctx() -> RlsResult<CPointer<EVP_MD_CTX>> {
        let md_ctx = CPointer::new(unsafe { EVP_MD_CTX_new() });
        if md_ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        Ok(md_ctx)
    }

    fn new_rsa(md_ctx: CPointer<EVP_MD_CTX>, pkey_ctx: Option<CPointer<EVP_PKEY_CTX>>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        if let Some(mut pkey_ctx) = pkey_ctx {
            unsafe { EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.as_mut_ptr(), signature.padding()) }.ok(RlsError::RsaSetPaddingError)?;
            if matches!(*signature,SignatureAlgorithm::RSA_PSS_RSAE_SHA256|SignatureAlgorithm::RSA_PSS_RSAE_SHA384|SignatureAlgorithm::RSA_PSS_RSAE_SHA512) {
                unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx.as_mut_ptr(), signature.evp_md()) }.ok(RlsError::SetRsaMgf1MdError)?;
                // saltLen = hashLen (32) —— TLS & RFC 推荐
                unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx.as_mut_ptr(), signature.salt_len()) }.ok(RlsError::SetRsaPassSaltLenError)?;
            }
            pkey_ctx.disable_auto_free();
        }
        Ok(AlgorithmSigner { md_ctx })
    }

    fn new_ec(md_ctx: CPointer<EVP_MD_CTX>, pkey_ctx: Option<CPointer<EVP_PKEY_CTX>>) -> RlsResult<AlgorithmSigner> {
        if let Some(mut pkey_ctx) = pkey_ctx {
            pkey_ctx.disable_auto_free();
        }
        Ok(AlgorithmSigner { md_ctx })
    }

    pub fn new_verify(pkey: &CPointer<EVP_PKEY>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = AlgorithmSigner::init_ctx()?;
        match *signature {
            SignatureAlgorithm::RSA_PKCS1_SHA1 => {
                unsafe { EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), null_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestVerifyError)?;
                AlgorithmSigner::new(md_ctx, None, signature)
            }
            _ => {
                let mut pkey_ctx = CPointer::nullptr();
                unsafe { EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), pkey_ctx.as_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestVerifyError)?;
                AlgorithmSigner::new(md_ctx, Some(pkey_ctx), signature)
            }
        }
    }

    fn new(md_ctx: CPointer<EVP_MD_CTX>, pkey_ctx: Option<CPointer<EVP_PKEY_CTX>>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        match signature.is_rsa() {
            true =>  AlgorithmSigner::new_rsa(md_ctx, pkey_ctx, signature),
            false => AlgorithmSigner::new_ec(md_ctx, pkey_ctx)
        }
    }

    pub fn new_sign(pkey: &CPointer<EVP_PKEY>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = AlgorithmSigner::init_ctx()?;
        match *signature {
            SignatureAlgorithm::RSA_PKCS1_SHA1 => {
                unsafe { EVP_DigestSignInit(md_ctx.as_mut_ptr(), null_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestSignError)?;
                AlgorithmSigner::new(md_ctx, None, signature)
            }
            _ => {
                let mut pkey_ctx = CPointer::nullptr();
                unsafe { EVP_DigestSignInit(md_ctx.as_mut_ptr(), pkey_ctx.as_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestSignError)?;
                AlgorithmSigner::new(md_ctx, Some(pkey_ctx), signature)
            }
        }
    }

    pub fn verify(&self, data: impl AsRef<[u8]>, signature: &[u8]) -> RlsResult<()> {
        unsafe {
            EVP_DigestVerify(
                self.md_ctx.as_mut_ptr(),
                signature.as_ptr(),
                signature.len(),
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::DigestVerifyError)
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        let mut len = 512;
        let mut out = vec![0; len];
        unsafe {
            EVP_DigestSign(
                self.md_ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::DigestSignError)?;
        out.truncate(len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::signature::{AlgorithmSigner, SignatureAlgorithm};
    use crate::Certificate;

    #[test]
    fn test_sign() {
        let der = hex::decode("308209eb308208d3a003020102020c5753597b3f311d38e6629529300d06092a864886f70d01010b05003050310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361312630240603550403131d476c6f62616c5369676e20525341204f562053534c2043412032303138301e170d3235303730393037303130325a170d3236303831303037303130315a308180310b300906035504061302434e3110300e060355040813076265696a696e673110300e060355040713076265696a696e6731393037060355040a13304265696a696e67204261696475204e6574636f6d20536369656e636520546563686e6f6c6f677920436f2e2c204c7464311230100603550403130962616964752e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100d096eace207d1338207c8c33b18c797e734db0a4a67a977c299d47c937e0fde98c35cea1a2e189573b2b5e7182506153485dacf900ca5809305f7dcabd3c7c4388b247a89d7cda9301229e65d4e04b596d4975251f80c20e5a8e2db5d126ad349004a355e94c768d186bb95cd321a08c70b08e45b96c5ff9358516927d46183c858807c4464d09522f99b9c3ae1696b07ca59b850e6ab2b4f56162f7c42ab3b1dfa18241290a8d8cfc5eb5e6d9cffdf759321ab1faa2b29e5877c0fa7b2b0eaa2c174f258bb6b7bcba715698f06ba0bfcef5479b52fedbfdd61395763fa9c4c72779c1eb666d930f236da7f1caec9e79d7db48f8acac0fac46e143bf80e0b18b0203010001a38206923082068e300e0603551d0f0101ff0404030205a0300c0603551d130101ff0402300030818e06082b06010505070101048181307f304406082b060105050730028638687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f67737273616f7673736c6361323031382e637274303706082b06010505073001862b687474703a2f2f6f6373702e676c6f62616c7369676e2e636f6d2f67737273616f7673736c63613230313830560603551d20044f304d304106092b06010401a03201143034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f3008060667810c010202303f0603551d1f043830363034a032a030862e687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f67737273616f7673736c6361323031382e63726c308203610603551d110482035830820354820962616964752e636f6d820c626169667562616f2e636f6d820c7777772e62616964752e636e82107777772e62616964752e636f6d2e636e820f6d63742e792e6e756f6d692e636f6d820b61706f6c6c6f2e6175746f820664777a2e636e820b2a2e62616964752e636f6d820e2a2e626169667562616f2e636f6d82112a2e62616964757374617469632e636f6d820e2a2e62647374617469632e636f6d820b2a2e6264696d672e636f6d820c2a2e68616f3132332e636f6d820b2a2e6e756f6d692e636f6d820d2a2e636875616e6b652e636f6d820d2a2e7472757374676f2e636f6d820f2a2e6263652e62616964752e636f6d82102a2e6579756e2e62616964752e636f6d820f2a2e6d61702e62616964752e636f6d820f2a2e6d62642e62616964752e636f6d82112a2e66616e79692e62616964752e636f6d820e2a2e62616964756263652e636f6d820c2a2e6d697063646e2e636f6d82102a2e6e6577732e62616964752e636f6d820e2a2e62616964757063732e636f6d820c2a2e6169706167652e636f6d820b2a2e6169706167652e636e820d2a2e626365686f73742e636f6d82102a2e736166652e62616964752e636f6d820e2a2e696d2e62616964752e636f6d82122a2e6261696475636f6e74656e742e636f6d820b2a2e646c6e656c2e636f6d820b2a2e646c6e656c2e6f726782122a2e647565726f732e62616964752e636f6d820e2a2e73752e62616964752e636f6d82082a2e39312e636f6d82122a2e68616f3132332e62616964752e636f6d820d2a2e61706f6c6c6f2e6175746f82122a2e7875657368752e62616964752e636f6d82112a2e626a2e62616964756263652e636f6d82112a2e677a2e62616964756263652e636f6d820e2a2e736d617274617070732e636e820d2a2e6264746a7263762e636f6d820c2a2e68616f3232322e636f6d820c2a2e68616f6b616e2e636f6d820f2a2e7061652e62616964752e636f6d82112a2e76642e62647374617469632e636f6d82112a2e636c6f75642e62616964752e636f6d8212636c69636b2e686d2e62616964752e636f6d82106c6f672e686d2e62616964752e636f6d8210636d2e706f732e62616964752e636f6d8210776e2e706f732e62616964752e636f6d82147570646174652e70616e2e62616964752e636f6d301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d23041830168014f8ef7ff2cd7867a8de6f8f248d88f1870302b3eb301d0603551d0e04160414ba917c55a98f1fb0026027bbd7d303af2dabad1d3082017e060a2b06010401d6790204020482016e0482016a0168007500acab30706cebec8431f413d2f4915f111e422443b1f2a68c4f3c2b3ba71e02c300000197edfcfd7d0000040300463044022035db4771c60e36d49e87469d8d5c1d197fa953c01a8f162dc2032b710bc61d530220220e91a8c5879393d64835f5247bf6f5ff3d56f39ddb4c72862d4aad774552cf007700cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e700000197edfcfd880000040300483046022100bcc9faf81a19cb22cfbf6da322f6a7367bc535a1a5f7ad23b8592d8b970968e3022100ab19f452a5fb57802c64f1a95fee77da7c977837858b0d41cc85803c2e715b81007600d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c5697700000197edfcfd60000004030047304502201e5f24191779dd66dab109b7119fda3c49a5217b101eff7c8fe8120b45fe38aa022100b797a9bda227a1087942b518de4e76c11d0d35acf5323b057c9d8c4c8777a80c300d06092a864886f70d01010b05000382010100023c79db06cfe80d96df8947293e8ad22fd3a2b41daec99aaee81db3d651de3b707e55896d01aef8eb8a76f055fe7243a3e038cea706ac978eabb7af87c52351832c1da4c243ade0ed9f7d935e1d27512632c6fa6962bbcfa65f4e89674543e505c7afec6eac225b2061299b19adc60d4fc7f45f772fb9a82a364db3755bb17da571b665aebbe47afe87b0330f4e2ba698865c15d6f50cfe6eb1288037acf489ce21a937619075b7c6d96742536949ce6d55942e075418597530b5cc5957255bfcf7afcf1eebec82d553d060cc1e7abbd25972f094c6fed8e1c1785dc7f48525a461345732b1fcf64c6cdf1b8d0d0bb5ef1f8c58c061e3f9c6c2c6075bf1c220").unwrap();
        let mut certificate = Certificate::from_der(&der).unwrap();
        drop(der);
        // certificate.verify_sni("m1.pxb7.com").unwrap();

        // let key = RsaKey::gen_new_key(2048).unwrap();
        let sign = AlgorithmSigner::new_verify(certificate.pub_key().unwrap(), &SignatureAlgorithm::RSA_PKCS1_SHA1).unwrap();
        let data = vec![27, 40, 224, 10, 150, 165, 57, 216, 0, 254, 231, 57, 97, 216, 8, 29, 17, 147, 112, 211, 166, 95, 165, 26, 61, 18, 197, 193, 138, 88, 56, 189, 105, 138, 12, 109, 99, 251, 198, 75, 236, 102, 170, 149, 167, 223, 89, 4, 165, 181, 125, 249, 86, 53, 251, 76, 179, 164, 190, 28, 222, 71, 223, 234, 3, 0, 23, 65, 4, 19, 119, 57, 150, 130, 216, 226, 112, 208, 184, 216, 53, 82, 84, 241, 53, 215, 215, 115, 162, 64, 92, 127, 156, 76, 28, 255, 114, 225, 94, 10, 6, 84, 105, 107, 164, 173, 140, 73, 121, 174, 68, 36, 235, 15, 71, 7, 103, 67, 205, 47, 242, 113, 9, 117, 220, 185, 116, 144, 153, 45, 137, 29, 210];
        let signature = hex::decode("42a2e98dfde9aadce324107649672d84a3ac57b83759b9b121930112df5a3f33b953a2adf4015da6435fd39d81b770c094c4e1731a90cb36aff5b7b66f7ef810f815ec6853d06b1802b58fa255ad0a860095a5164c0c0ea1ec9025dfcfafe3abee8ed986d40993e4eeb0f1c0105106fcd8717400b1dca91878dc21e1be102eaf7fd12da4f96e36a48e67adab76b8047ba0a01ea9bee995c6bbb4143e654e0d4f5fc789c8c1cdd57fd366c26c8b895b725b76226090cd9ef1db197598df34dedc87aa590a28dfdcc95ca2b783bc9d9f84c13a3e0b37665b9a02f917d71e534f27bbbddc37f88af9a0a723925395b4869a154d0034490711da11d1eb5a4298b366").unwrap();
        sign.verify(data, &signature).unwrap();
        // let sign = sign.sign("data").unwrap();
        // println!("{} {:x?}", sign.len(), sign);
    }
}