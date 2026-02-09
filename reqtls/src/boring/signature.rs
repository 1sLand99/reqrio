use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use std::ptr::null_mut;
use crate::boring::ffi::CPointerMut;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureAlgorithm {
    RSA_PKCS1_SHA1 = 0x0201,
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
    RSA_PSS_PSS_SHA256 = 0x0807,
    RSA_PSS_PSS_SHA384 = 0x0808,
    RSA_PSS_PSS_SHA512 = 0x0809,

    ED25519 = 0x080A,
    ED448 = 0x080B,

    ECDSA_SHA1 = 0x0203,
    ECDSA_SECP256R1_SHA256 = 0x0403,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
    SHA1_DSA = 0x0202,
    SHA224_RSA = 0x0301,
    SHA224_DSA = 0x0302,
    SHA224_ECDSA = 0x0303,
    SHA256_DSA = 0x0402,
    SHA384_DSA = 0x0502,
    SHA512_DSA = 0x0602,
}

impl SignatureAlgorithm {
    pub fn from_u16(value: u16) -> Option<SignatureAlgorithm> {
        match value {
            0x0201 => Some(SignatureAlgorithm::RSA_PKCS1_SHA1),
            0x0401 => Some(SignatureAlgorithm::RSA_PKCS1_SHA256),
            0x0501 => Some(SignatureAlgorithm::RSA_PKCS1_SHA384),
            0x0601 => Some(SignatureAlgorithm::RSA_PKCS1_SHA512),
            0x0804 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA256),
            0x0805 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA384),
            0x0806 => Some(SignatureAlgorithm::RSA_PSS_RSAE_SHA512),
            0x0807 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA256),
            0x0808 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA384),
            0x0809 => Some(SignatureAlgorithm::RSA_PSS_PSS_SHA512),
            0x080A => Some(SignatureAlgorithm::ED25519),
            0x080B => Some(SignatureAlgorithm::ED448),
            0x0203 => Some(SignatureAlgorithm::ECDSA_SHA1),
            0x0403 => Some(SignatureAlgorithm::ECDSA_SECP256R1_SHA256),
            0x0503 => Some(SignatureAlgorithm::ECDSA_SECP384R1_SHA384),
            0x0603 => Some(SignatureAlgorithm::ECDSA_SECP521R1_SHA512),
            0x0202 => Some(SignatureAlgorithm::SHA1_DSA),
            0x0301 => Some(SignatureAlgorithm::SHA224_RSA),
            0x0302 => Some(SignatureAlgorithm::SHA224_DSA),
            0x0303 => Some(SignatureAlgorithm::SHA224_ECDSA),
            0x0402 => Some(SignatureAlgorithm::SHA256_DSA),
            0x0502 => Some(SignatureAlgorithm::SHA384_DSA),
            0x0602 => Some(SignatureAlgorithm::SHA512_DSA),
            _ => None
        }
    }

    pub fn all() -> Vec<SignatureAlgorithm> {
        vec![
            SignatureAlgorithm::RSA_PKCS1_SHA1,
            SignatureAlgorithm::RSA_PKCS1_SHA256,
            SignatureAlgorithm::RSA_PKCS1_SHA384,
            SignatureAlgorithm::RSA_PKCS1_SHA512,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
            SignatureAlgorithm::RSA_PSS_PSS_SHA256,
            SignatureAlgorithm::RSA_PSS_PSS_SHA384,
            SignatureAlgorithm::RSA_PSS_PSS_SHA512,
            SignatureAlgorithm::ED25519,
            SignatureAlgorithm::ED448,
            SignatureAlgorithm::ECDSA_SHA1,
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512,
            SignatureAlgorithm::SHA1_DSA,
            SignatureAlgorithm::SHA224_RSA,
            SignatureAlgorithm::SHA224_DSA,
            SignatureAlgorithm::SHA224_ECDSA,
            SignatureAlgorithm::SHA256_DSA,
            SignatureAlgorithm::SHA384_DSA,
            SignatureAlgorithm::SHA512_DSA,
        ]
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }

    fn evp_md(&self) -> *const EVP_MD {
        match self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => unsafe { EVP_sha256() }
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => unsafe { EVP_sha512() }
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => unsafe { EVP_sha256() }
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => unsafe { EVP_sha512() }
            SignatureAlgorithm::RSA_PKCS1_SHA256 => unsafe { EVP_sha256() },
            SignatureAlgorithm::RSA_PKCS1_SHA384 => unsafe { EVP_sha384() }
            SignatureAlgorithm::RSA_PKCS1_SHA512 => unsafe { EVP_sha512() }
            _ => panic!("unsupported signature algorithm"),
        }
    }

    fn padding(&self) -> i32 {
        match self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => RSA_PKCS1_PSS_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA256 => RSA_PKCS1_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA384 => RSA_PKCS1_PADDING,
            SignatureAlgorithm::RSA_PKCS1_SHA512 => RSA_PKCS1_PADDING,
            _ => panic!("unsupported signature algorithm"),
        }
    }

    fn salt_len(&self) -> i32 {
        match self {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => 32,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => 48,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => 64,
            _ => panic!("unsupported signature algorithm"),
        }
    }
}

pub struct AlgorithmSigner {
    md_ctx: CPointerMut<EVP_MD_CTX>,
}

impl AlgorithmSigner {
    fn init_ctx() -> RlsResult<CPointerMut<EVP_MD_CTX>> {
        let md_ctx = CPointerMut::new(unsafe { EVP_MD_CTX_new() });
        if md_ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        Ok(md_ctx)
    }

    fn new_rsa(md_ctx: CPointerMut<EVP_MD_CTX>, mut pkey_ctx: CPointerMut<EVP_PKEY_CTX>, signature: SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        unsafe { EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.as_mut_ptr(), signature.padding()) }.ok(RlsError::RsaSetPaddingError)?;
        if matches!(signature,SignatureAlgorithm::RSA_PSS_RSAE_SHA256|SignatureAlgorithm::RSA_PSS_RSAE_SHA384|SignatureAlgorithm::RSA_PSS_RSAE_SHA512) {
            unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx.as_mut_ptr(), signature.evp_md()) }.ok(RlsError::SetRsaMgf1MdError)?;
            // saltLen = hashLen (32) —— TLS & RFC 推荐
            unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx.as_mut_ptr(), signature.salt_len()) }.ok(RlsError::SetRsaPassSaltLenError)?;
        }
        pkey_ctx.disable_auto_free();
        Ok(AlgorithmSigner { md_ctx })
    }

    fn new_ec(md_ctx: CPointerMut<EVP_MD_CTX>, mut pkey_ctx: CPointerMut<EVP_PKEY_CTX>) -> RlsResult<AlgorithmSigner> {
        pkey_ctx.disable_auto_free();
        Ok(AlgorithmSigner { md_ctx })
    }

    pub fn new_verify(pkey: &CPointerMut<EVP_PKEY>, signature: SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = AlgorithmSigner::init_ctx()?;
        let mut pkey_ctx = CPointerMut::nullptr();
        unsafe { EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), pkey_ctx.as_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestVerifyError)?;
        AlgorithmSigner::new(md_ctx, pkey_ctx, signature)
    }

    fn new(md_ctx: CPointerMut<EVP_MD_CTX>, pkey_ctx: CPointerMut<EVP_PKEY_CTX>, signature: SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        match signature {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 | SignatureAlgorithm::RSA_PSS_RSAE_SHA384 | SignatureAlgorithm::RSA_PSS_RSAE_SHA512
            | SignatureAlgorithm::RSA_PKCS1_SHA256 | SignatureAlgorithm::RSA_PKCS1_SHA384 | SignatureAlgorithm::RSA_PKCS1_SHA512 => AlgorithmSigner::new_rsa(md_ctx, pkey_ctx, signature),
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 | SignatureAlgorithm::ECDSA_SECP384R1_SHA384 | SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => AlgorithmSigner::new_ec(md_ctx, pkey_ctx),
            _ => Err("unsupported signature".into())
        }
    }

    pub fn new_sign(pkey: &CPointerMut<EVP_PKEY>, signature: SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = AlgorithmSigner::init_ctx()?;
        let mut pkey_ctx = CPointerMut::nullptr();
        unsafe { EVP_DigestSignInit(md_ctx.as_mut_ptr(), pkey_ctx.as_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestSignError)?;
        AlgorithmSigner::new(md_ctx, pkey_ctx, signature)
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
        let der = hex::decode("308203a73082034da003020102021100f5f67b2093e6ff940e660079e5e7323e300a06082a8648ce3d040302303b310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573310c300a06035504031303574531301e170d3236303230313132313631325a170d3236303530323133313433365a3017311530130603550403130c7a686966617a68652e746f703059301306072a8648ce3d020106082a8648ce3d030107034200046a5cba8c2d113a9c39261d70112d3e04ea434e886cf1d2f0d5d121671e5d908f99e2129ac108683bbd9e8d098db24b080fd1b1441f099ec2094708543921a1d2a382025430820250300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e041604141edf22f3430b5eb95f03e78bcf6baed1e94e72ca301f0603551d230418301680149077923567c4ffa8cca9e67bd980797bcc93f938305e06082b0601050507010104523050302706082b06010505073001861b687474703a2f2f6f2e706b692e676f6f672f732f7765312f396659302506082b060105050730028619687474703a2f2f692e706b692e676f6f672f7765312e63727430270603551d110420301e820c7a686966617a68652e746f70820e2a2e7a686966617a68652e746f7030130603551d20040c300a3008060667810c01020130360603551d1f042f302d302ba029a0278625687474703a2f2f632e706b692e676f6f672f7765312f67784942763642326859772e63726c30820103060a2b06010401d6790204020481f40481f100ef0076000e5794bcf3aea93e331b2c9907b3f790df9bc23d713225dd21a925ac61c54e210000019c1958bf7700000403004730450220474f227a901c1cbc9bd080b65f215ab462f3fd16cfdb38a7a05f3108e48123f6022100833fd36458df9e2e4666fc9f95c1f6da0207c2e3331f938a52635e8a83a2fcf800750016832dabf0a9250f0ff03aa545ffc8bfc823d0874bf6042927f8e71f3313f5fa0000019c1958bf9000000403004630440220521cefa48dad1fdd50ce6977077fe51607cf4fceb5e282175e7dd4927e758dd202207e8e9ed446b65e13965a322607afd66de76941590acf5e42c2eb1dc1adeaa845300a06082a8648ce3d0403020348003045022041ed9f8ca35c582049360ddd00ab480f7531d1ffeb446c054c1bee89a1dfad6d022100849aeaa719acfa8acfbc471e17acd67c81137e532eb2f822aaab8924085e716c").unwrap();
        let mut certificate = Certificate::from_der(&der).unwrap();
        drop(der);
        // certificate.verify_sni("m1.pxb7.com").unwrap();

        // let key = RsaKey::gen_new_key(2048).unwrap();
        let sign = AlgorithmSigner::new_verify(certificate.pub_key().unwrap(), SignatureAlgorithm::ECDSA_SECP256R1_SHA256).unwrap();
        let data = vec![222, 5, 40, 78, 60, 157, 158, 31, 41, 107, 228, 17, 120, 231, 193, 86, 172, 163, 46, 135, 47, 196, 207, 210, 110, 188, 242, 8, 214, 186, 222, 31, 105, 130, 249, 181, 90, 88, 18, 74, 218, 239, 250, 217, 83, 58, 253, 55, 109, 80, 45, 239, 89, 27, 100, 103, 68, 79, 87, 78, 71, 82, 68, 1, 3, 0, 29, 32, 85, 171, 63, 138, 57, 16, 252, 246, 128, 200, 141, 222, 72, 111, 113, 116, 95, 200, 175, 51, 22, 204, 188, 237, 11, 62, 143, 244, 126, 115, 40, 47];
        let signature = hex::decode("304502206601d541286ba8526764b24181c089fe292909865ae10239bcaac0073946ccb3022100bf4287115dd5a1a92f2ecd51ec5f6782c4c2b2c811d5031b5aba5884c7abc683").unwrap();
        sign.verify(data, &signature).unwrap();
        // let sign = sign.sign("data").unwrap();
        // println!("{} {:x?}", sign.len(), sign);
    }
}