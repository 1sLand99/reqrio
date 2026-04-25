use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;
use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;

#[derive(Clone, Copy)]
pub struct SignatureAlgorithm(u16);

impl SignatureAlgorithm {
    pub fn new(v: u16) -> SignatureAlgorithm { SignatureAlgorithm(v) }

    pub fn into_inner(self) -> u16 { self.0 }

    pub fn as_u16(&self) -> u16 { self.0 }

    fn evp_md(&self) -> *const EVP_MD {
        match self.0 {
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
        match self.0 {
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
        match self.0 {
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256 => 32,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA384 => 48,
            SignatureAlgorithm::RSA_PSS_RSAE_SHA512 => 64,
            _ => panic!("unsupported signature algorithm"),
        }
    }
}

impl SignatureAlgorithm {
    pub const RSA_PKCS1_SHA1: u16 = 0x0201;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0807;
    pub const RSA_PSS_PSS_SHA384: u16 = 0x0808;
    pub const RSA_PSS_PSS_SHA512: u16 = 0x0809;
    pub const ED25519: u16 = 0x080A;
    pub const ED448: u16 = 0x080B;
    pub const ECDSA_SHA1: u16 = 0x0203;
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    pub const SHA1_DSA: u16 = 0x0202;
    pub const SHA224_RSA: u16 = 0x0301;
    pub const SHA224_DSA: u16 = 0x0302;
    pub const SHA224_ECDSA: u16 = 0x0303;
    pub const SHA256_DSA: u16 = 0x0402;
    pub const SHA384_DSA: u16 = 0x0502;
    pub const SHA512_DSA: u16 = 0x0602;

    pub const ALL: [u16; 23] = [0x0201, 0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B, 0x0203, 0x0403, 0x0503, 0x0603, 0x0202, 0x0301, 0x0302, 0x0303, 0x0402, 0x0502, 0x0602];
    pub fn spec(&self) -> &'static str {
        match self.0 {
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

impl From<u16> for SignatureAlgorithm {
    fn from(v: u16) -> SignatureAlgorithm { SignatureAlgorithm(v) }
}

impl PartialEq<u16> for &SignatureAlgorithm {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
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
    fn new_rsa(md_ctx: CPointer<EVP_MD_CTX>, pkey_ctx: Option<CPointer<EVP_PKEY_CTX>>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        if let Some(mut pkey_ctx) = pkey_ctx {
            unsafe { EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.as_mut_ptr(), signature.padding()) }.ok(RlsError::RsaSetPaddingError)?;
            if matches!(signature.as_u16(), SignatureAlgorithm::RSA_PSS_RSAE_SHA256|SignatureAlgorithm::RSA_PSS_RSAE_SHA384|SignatureAlgorithm::RSA_PSS_RSAE_SHA512) {
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

    pub(crate) fn new_verify(pkey: &CPointer<EVP_PKEY>, signature: impl Into<SignatureAlgorithm>) -> RlsResult<AlgorithmSigner> {
        let md_ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, RlsError::InitEvpCtxError)?;
        let signature = signature.into();
        match signature.as_u16() {
            SignatureAlgorithm::RSA_PKCS1_SHA1 => {
                unsafe { EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), null_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestVerifyError)?;
                AlgorithmSigner::new(md_ctx, None, &signature)
            }
            _ => {
                let mut pkey_ctx = CPointer::nullptr();
                unsafe { EVP_DigestVerifyInit(md_ctx.as_mut_ptr(), pkey_ctx.as_mut(), signature.evp_md(), null_mut(), pkey.as_mut_ptr()) }.ok(RlsError::DigestVerifyError)?;
                AlgorithmSigner::new(md_ctx, Some(pkey_ctx), &signature)
            }
        }
    }

    fn new(md_ctx: CPointer<EVP_MD_CTX>, pkey_ctx: Option<CPointer<EVP_PKEY_CTX>>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        match signature.is_rsa() {
            true => AlgorithmSigner::new_rsa(md_ctx, pkey_ctx, signature),
            false => AlgorithmSigner::new_ec(md_ctx, pkey_ctx)
        }
    }

    pub(crate) fn new_sign(pkey: &CPointer<EVP_PKEY>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, RlsError::InitEvpCtxError)?;
        match signature.as_u16() {
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
    use crate::boring::certificate::ROOT_STORES;
    use crate::{AlgorithmSigner, Certificate, SignatureAlgorithm};

    #[test]
    fn test_sign() {
        let mut cert = Certificate::from_pem(r#"-----BEGIN CERTIFICATE-----
MIIE9jCCA96gAwIBAgISBQ+X8QE48dpOklzldVn/OEVOMA0GCSqGSIb3DQEBCwUA
MDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQD
EwNSMTMwHhcNMjYwMjI4MDgwODMzWhcNMjYwNTI5MDgwODMyWjAZMRcwFQYDVQQD
Ew50bHMuMTIzNDA4Lnh5ejCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALSZ5Ue1uJnWxcnJB4X6RBUjAiI05IPn0QwkbWr9rYt8SFPCAHYb8NBOsz/OnnYT
q1ON1dWRNjX0mXddCTB28Bh7QZXa4ie84XsPnTvKbz7z3CXu72hveOC7SD9pT0eP
hY49v9/clR1U+XWAui04uLwB6VqD0ddFW4v3MNdLq0AtCLdQJl0jYt664RsMaJAg
j969wXBmoYSFWnFPniFlxCsnf2SYt9JSjYtqdnpW0G/LIqo9sq89KM9LqXJfHP0n
G8ceGzoLSDFuoWBk/LXGLqG5sywAoAQr+2/o3YN0FfHvFiYY+TmaLfg+UnN+Hg9U
qgNVufupY6SL/1/62Sk4xisCAwEAAaOCAhwwggIYMA4GA1UdDwEB/wQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQtKSSH
vO8eMUq5jFLh9cCyEurVYzAfBgNVHSMEGDAWgBTnq58PLDOgU9NeT3jIsoQOO9aS
MzAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAKGF2h0dHA6Ly9yMTMuaS5sZW5j
ci5vcmcvMBkGA1UdEQQSMBCCDnRscy4xMjM0MDgueHl6MBMGA1UdIAQMMAowCAYG
Z4EMAQIBMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9yMTMuYy5sZW5jci5vcmcv
NzkuY3JsMIIBDAYKKwYBBAHWeQIEAgSB/QSB+gD4AHYAyzj3FYl8hKFEX1vB3fvJ
bvKaWc1HCmkFhbDLFMMUWOcAAAGco4BY1gAABAMARzBFAiEAqb4z1dtrMB2nceBM
AaBP7D9vDrRwVQuAKUT783XJPcMCIA0NiEsEVzx6iSxSjG3EvEnoq24fe02Cgr8t
HZhmW0wVAH4AGoudaUpXmMiZoMqIvfSPwLRWYMzDYA0fcfRp/8fRrKMAAAGco4BZ
vwAIAAAFAE+21zYEAwBHMEUCIH6V4LfIwu2sYmzLjMgir+sYrI1zUGxY/Af5p6P+
cd6YAiEAxw5hKmb4PehE5DWU7DB9oTQxm9vEkvlI1+jvvA+xHbQwDQYJKoZIhvcN
AQELBQADggEBAHvDI9LOD/cd7Wn3OYA0k3hDIobR1m4ZjopAzRd7nMq+sANYMLo5
tSYJ8jManb8a/2WlipnYJxbgjgVOVW+M4yZLQ1xSty4EeFB6WRdnOomHwHozExgm
r3yOtSpPrPRoGS/tYgMB69Nm44OsRvZErigErU5ajSmvA/6Gk9x/fAjXFNaHJuaY
lMjhD8zeqaEiaYoo3LaaChtuGeHhQ0iDIK7FKM2lPRHHK2CcwRxIW4UVsnz+0mna
g9U5uU08VzDV+0LlZXpkCTH5IPlf7JucxTsO0W0uEfUCzLPl8CufKtfV5Mn2q9SA
Ep0DDNAFIybHWSxAYZ8S6I2Jl9ET4tbakNY=
-----END CERTIFICATE-----"#).unwrap();
        cert[0].get_aia().unwrap();
        ROOT_STORES.verify_cert(&mut cert, &vec![], "tls.123408.xyz").unwrap();


        let sign_data = [32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121, 0, 228, 108, 89, 30, 10, 20, 30, 210, 236, 32, 193, 54, 153, 237, 70, 29, 180, 105, 130, 182, 9, 218, 124, 199, 31, 199, 114, 215, 126, 59, 75, 12, 28, 110, 3, 90, 149, 100, 238, 198, 132, 93, 254, 191, 141, 132, 108, 252];
        let sign = hex::decode("2bc628b1e50de0ad6ba33a3a4d758eec8377f8e86c9cf3d2eb6a8e965bb31666662d54f57b657a4f282e56469fcef3c4d711f261bc92b4356763f8f5b221512955ea66408eeb9be06c9863f8991ffc7a0ab97d1e8c3d2000941af32d06ef4ab18b593558a4be18c7baee807b8a8eb261b3001c07838ef6efe9ebaff0398ff86458551f45295adab38052e95e2ed5e3d435afcac41a38de68d0633b6c0c2aaabeacd8fd23630404a4407be2417df655c725321a2a231ef2700289bd2983ad0a6fe75c8dd6bcb07a55abbe2e0ef4aa695c1215df1b1451f1c7528a4b3596ebc055cdf2ca5994de33d7a3c33f591bc0b0e7e6feb603dce15f66577e8983abbc46a3").unwrap();
        let cert = "30820e1a30820c02a0030201020213430003a5985b1d66d63b2b202700000003a598300d06092a864886f70d01010c05003057310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312830260603550403131f4d6963726f736f667420544c5320473220525341204341204f435350203034301e170d3236303230323139313334345a170d3236303830313139313334345a3063310b3009060355040613025553310b30090603550408130257413110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e311530130603550403130c7777772e62696e672e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100ba9f82f55d068058e5e7b31748607877e025681708129f2ab62139ba0c499d7733182fb3de60eefe8f9bb4b6d908f1bbb77f2f0a089caaf698d02f15c40d80b0c362b7c303fac7026fc1309705394b2cec12a0c5fdfebd77ae292b03b32e214ea572890a306f43c92595af8259156fae522e39e6504bb03b94c424d7ad218c626a0b38cb398dfd80ae82f284b7859e231c5352b55b880a06f763bbea70b797feb292692c9729bd2f608f5bd3c5c11d0f38ea17d80457a5845409b38c40ec56fcd0df28267fe8ab3f76be264252d3038cf61b2551db6dcfd99032e4ff76462c6fb408165cf851a4775e0046b1893124fe4e34842996614f1c82b88d0c246c52910203010001a38209d1308209cd3082017b060a2b06010401d6790204020482016b048201670165007500d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c569770000019c1fcfac6e000004030046304402206da84d4b12f6df53f17193c5ef32bf8e35c07126ba7ffb7a4b58e775cb71c17a022044558592a9c1c0bcba8022957226b225d8da5cbe3fcd449335bdde9150aa01c7007500c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd0000019c1fcfac78000004030046304402202fe0288452d45e426bbcddac6242de4504614916b96537274189547dc0a3902c022003b6cc523e15b5b250aadb7143c9bd7c2e042270478b0ce9ff0bafcf2cdd0e26007500c8a3c47fc7b3adb9356b013f6a7a126de33a4e43a5c646f997ad3975991dcf9a0000019c1fcfaca7000004030046304402206f683a1e5bb5222ade44461cfa69044d6d8178b4f3afcfca3f977da8e51af04d02200bbe45aa346f25081345f4b96cd9f290127fe43aef360d196be72ff616d3d61b301b06092b060104018237150a040e300c300a06082b06010505070301303c06092b0601040182371507042f302d06252b060104018237150887bdd71b81e7eb4682819d2e8ed00c87f0da1d5d83e9c36782b4a34c0201640201203082010b06082b060105050701010481fe3081fb306106082b060105050730028655687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63657274732f4d6963726f736f6674253230544c53253230473225323052534125323043412532304f43535025323030342e637274306706082b06010505073002865b687474703a2f2f6361697373756572732e6d6963726f736f66742e636f6d2f706b696f70732f63657274732f4d6963726f736f6674253230544c53253230473225323052534125323043412532304f43535025323030342e637274302d06082b060105050730018621687474703a2f2f6f6e656f6373702e6d6963726f736f66742e636f6d2f6f637370301d0603551d0e0416041451bafc0929e76e443d5eafa1e5bcad03b574b784300e0603551d0f0101ff0404030205a0308205110603551d11048205083082050482132a2e706c6174666f726d2e62696e672e636f6d820a2a2e62696e672e636f6d820862696e672e636f6d821669656f6e6c696e652e6d6963726f736f66742e636f6d82132a2e77696e646f77737365617263682e636f6d8219636e2e69656f6e6c696e652e6d6963726f736f66742e636f6d82112a2e6f726967696e2e62696e672e636f6d820d2a2e6d6d2e62696e672e6e6574820e2a2e6170692e62696e672e636f6d820d2a2e636e2e62696e672e6e6574820d2a2e636e2e62696e672e636f6d821073736c2d6170692e62696e672e636f6d821073736c2d6170692e62696e672e6e6574820e2a2e6170692e62696e672e6e6574820e2a2e62696e67617069732e636f6d820f62696e6773616e64626f782e636f6d8216666565646261636b2e6d6963726f736f66742e636f6d821b696e736572746d656469612e62696e672e6f66666963652e6e6574820e722e6261742e62696e672e636f6d82102a2e722e6261742e62696e672e636f6d820f2a2e646963742e62696e672e636f6d820e2a2e73736c2e62696e672e636f6d82102a2e61707065782e62696e672e636f6d82162a2e706c6174666f726d2e636e2e62696e672e636f6d820d77702e6d2e62696e672e636f6d820c2a2e6d2e62696e672e636f6d820f676c6f62616c2e62696e672e636f6d821177696e646f77737365617263682e636f6d820e7365617263682e6d736e2e636f6d82112a2e62696e6773616e64626f782e636f6d82192a2e6170692e74696c65732e646974752e6c6976652e636f6d82182a2e74302e74696c65732e646974752e6c6976652e636f6d82182a2e74312e74696c65732e646974752e6c6976652e636f6d82182a2e74322e74696c65732e646974752e6c6976652e636f6d82182a2e74332e74696c65732e646974752e6c6976652e636f6d820b33642e6c6976652e636f6d82136170692e7365617263682e6c6976652e636f6d8214626574612e7365617263682e6c6976652e636f6d8215636e7765622e7365617263682e6c6976652e636f6d820d646974752e6c6976652e636f6d821166617265636173742e6c6976652e636f6d820e696d6167652e6c6976652e636f6d820f696d616765732e6c6976652e636f6d82116c6f63616c2e6c6976652e636f6d2e617582146c6f63616c7365617263682e6c6976652e636f6d82146c7334642e7365617263682e6c6976652e636f6d820d6d61696c2e6c6976652e636f6d82116d6170696e6469612e6c6976652e636f6d820e6c6f63616c2e6c6976652e636f6d820d6d6170732e6c6976652e636f6d82106d6170732e6c6976652e636f6d2e6175820f6d696e6469612e6c6976652e636f6d820d6e6577732e6c6976652e636f6d821c6f726967696e2e636e7765622e7365617263682e6c6976652e636f6d8216707265766965772e6c6f63616c2e6c6976652e636f6d820f7365617263682e6c6976652e636f6d8212746573742e6d6170732e6c6976652e636f6d820e766964656f2e6c6976652e636f6d820f766964656f732e6c6976652e636f6d82157669727475616c65617274682e6c6976652e636f6d820c7761702e6c6976652e636f6d82127765626d61737465722e6c6976652e636f6d82157777772e6c6f63616c2e6c6976652e636f6d2e617582147777772e6d6170732e6c6976652e636f6d2e617582137765626d6173746572732e6c6976652e636f6d821865636e2e6465762e7669727475616c65617274682e6e6574820c7777772e62696e672e636f6d300c0603551d130101ff040230003081f10603551d1f0481e93081e63081e3a081e0a081dd866c687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63726c2f706172746974696f6e2f4d6963726f736f6674253230544c53253230473225323052534125323043412532304f43535025323030345f506172746974696f6e30303035332e63726c866d687474703a2f2f63726c322e6d6963726f736f66742e636f6d2f706b696f70732f63726c2f706172746974696f6e2f4d6963726f736f6674253230544c53253230473225323052534125323043412532304f43535025323030345f506172746974696f6e30303035332e63726c30660603551d20045f305d3008060667810c0102023051060c2b0601040182374c837d01013041303f06082b060105050702011633687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f446f63732f5265706f7369746f72792e68746d301f0603551d23041830168014540cbcec18f77df103e284be34644467cf751f6530130603551d25040c300a06082b06010505070301300d06092a864886f70d01010c0500038202010039291b8c425b3e4e2cf124f6ffc35ae1f8b087ca96ecf0d12e890bf34ef361bd4a05a3eecc144b1b6a9dd1e243134c32fea8e9ab5f8ba4a34a4a21a558065a794ccf57e82829e1805d9c88d32dd22a50cfeb7f95a809f2cb475a8e5bcd86a9b4254c811e9d58308bf86481e305c522141ce03ebcb6ecc6abc53842ac603b8867423b986852b8b62950efcefcedaa893676789043e2bbd77950c45aeb17ae1643439036fc0f4b6b773904c43791f36901a393e9d94ef1fe86585792670f5686ee049244a1223b64bb0987c0593114711224cf90bb1ec78dc915179462a1fb3406d5571c60d65b195d083da5b3394ddbd650a00b11133ca30a5cc34df7870aa224e0817b7a71edea7330d4e5c6b96b7ec55502678ab836ddbf99279672fd3640b23495d39a399cfd6bf73e4e84123066c3d413d21f3cfa9cbc7a98e8a6e6353e6910ba093f7423dd774b2dc421accafa72f92f23ee7163435ecbaa64f63d1ff0f0ca9afc4065cfed6b7e6d2948f7329ac2f868c0388e94955672a946251501423eb744532dec346dd9ceca58b28560917a32960b0a288390dcafc6f954cc604be72ee33c40c7b3e6b93072e14afebed845e25c2a71011f49f499b5a8b1297ac81b0f169c72f4f4c5f60b9fe39d58fd911a3a434cf4958b54db69f8a5447010f057e43e7115a251d7f7d30bcf80aa21a7063daf2e449c1e669278ad64ab0dc0902e";
        let mut cert = Certificate::from_der(hex::decode(cert).unwrap()).unwrap();
        let signer = AlgorithmSigner::new_verify(cert.pub_key().unwrap(), SignatureAlgorithm::RSA_PSS_RSAE_SHA256).unwrap();
        signer.verify(sign_data, &sign).unwrap();
    }
}