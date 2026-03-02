use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;
use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;

#[derive(PartialEq, Clone)]
pub struct SignatureAlgorithm(u16);

impl SignatureAlgorithm {
    pub fn new(v: u16) -> SignatureAlgorithm { SignatureAlgorithm(v) }

    pub fn into_inner(self) -> u16 { self.0 }

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
        let md_ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, RlsError::InitEvpCtxError)?;
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
            true => AlgorithmSigner::new_rsa(md_ctx, pkey_ctx, signature),
            false => AlgorithmSigner::new_ec(md_ctx, pkey_ctx)
        }
    }

    pub fn new_sign(pkey: &CPointer<EVP_PKEY>, signature: &SignatureAlgorithm) -> RlsResult<AlgorithmSigner> {
        let md_ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, RlsError::InitEvpCtxError)?;
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
    use crate::boring::certificate::ROOT_STORES;
    use crate::Certificate;

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
        ROOT_STORES.verify_cert(&mut cert, "tls.123408.xyz").unwrap();


        // let mut certs = vec![];
        // let der = hex::decode("308204d4308202bca00302010202142bafbbe1184c5973c25728f1e576d8a998881e1d300d06092a864886f70d01010b05003062310b300906035504060c02434e3112301006035504080c094775616e67646f6e673112301006035504070c094775616e677a686f75310c300a060355040a0c03584c58310c300a060355040b0c03584c58310f300d06035504030c06584c582043413020170d3236303230353036323035305a180f32303536303132393036323035305a3063310b300906035504060c02434e3112301006035504080c094775616e67646f6e673112301006035504070c094775616e677a686f75310b3009060355040a0c02584c310b3009060355040b0c02584c3112301006035504030c09584c2053455256455230820122300d06092a864886f70d01010105000382010f003082010a0282010100c35b8e2787e6f688120c2b789ba7fb52f8f869648e9e2342389b740c3f76ab3e5bd70f27033f058ab6381f05a79d105aba1c1382008defd47a66cf13a5f69e25f5955374695643d28b12b717562f57a343e38aa08ab33e7f395e3204d8e9cd9ca33447bdea8c1668412ab458b2daf7dbba3e2eefeba38eef0772f99f4cd20d15bac074910e45f4ee2f3cf26efb56f52479ac1ed5cea0fff6ee4e1da00ee15c91b5e927d24f3e33fa9207d45c10e4b1f71061f04f8f6360c92777ffa407d20ee04ad2bd202bb85b39930dcc05e111455acf873bdd2a99f4e845926542663d3de9f9c19cfb1c4771a00a15325e706145de51eea709a6fc0cff814ffdc2cc51c3a70203010001a37f307d303a0603551d1104333031820f64656275672e786c6c676c2e746f70820d7777772e786c6c676c2e746f708209786c6c676c2e746f70870400000000300f0603551d0f0101ff0405030307c000301d0603551d0e0416041495304ae726deac290907c38d9c7a17844b7b00a4300f0603551d130101ff04053003010100300d06092a864886f70d01010b050003820201004f8214773049e7522a8a22e9f0ea3ed906b97e842c4a6ce4974f4f8fc15dd9a81ef5753525285d62dacfc5b7155d55b1535d6eb3219ccadd7666ec2b8d40f230ed34c5136f2dc4d464d40eb7d55cf5f731314ba82d26860cad74bbd1ba75c245d22ace9b64fc72359c2c63e91c4f8f5c5641fb290613694ec7b4b63cf7e4c1265dcff3c169143ce79de16ba9077e48f9432e4e3cfa8bbf0beb4eabb61fc183add8a2542d6ec0901e209fe657dcc4477125b802cff2f2458155f015f1b0c7c4d793eacc0f8e6bd11b521b8456a9b6e974c8e600e9ab5964dcd88d5565cc229c7f4560f5572c62d743d2c5775b843834f4adb9e2dbead3904d66785537f124c1d72034ea6e875ec24c9361eb91f1c05d6ae1171e1b9925b0cf38700b7ec975876068038487e5f87794ffc605b4b39ae4ba1b74919919e4d1bd5279abcc76c0771dc7791530829c15be13df7b9dae28f097761ae681beb50ab21c79600b02ee28d8d7a8f76b43898bf1c9d9cfdad221290286d084bee98e3161b59ad2b814293e7cc83acf657da2d92cc2b315d797f98706c8c742cfbacf53496f032f9d82443e65928dba0423b74c5f914e155405236fcc26f4aabbfd67a0e7fe5ad38e9a52160c12c360abc4d7206ac96eb3d7858aca1870f67e97b3a3691f1e4172dcbcd74b2ecd04bb1a1475275ad10474194f08c59200bc337946c893ed092fe70801fa67a0").unwrap();
        // certs.push(Certificate::from_der(&der).unwrap());
        // let der = hex::decode("308205973082037fa003020102021436d789e8813a9f3e04509efed1ee74b9ee98f2c8300d06092a864886f70d01010b05003062310b300906035504060c02434e3112301006035504080c094775616e67646f6e673112301006035504070c094775616e677a686f75310c300a060355040a0c03584c58310c300a060355040b0c03584c58310f300d06035504030c06584c582043413020170d3236303230353036323034395a180f32303536303132393036323034395a3062310b300906035504060c02434e3112301006035504080c094775616e67646f6e673112301006035504070c094775616e677a686f75310c300a060355040a0c03584c58310c300a060355040b0c03584c58310f300d06035504030c06584c5820434130820222300d06092a864886f70d01010105000382020f003082020a02820201009da3fd32aa02914010d40ba8c55b0b3939abb430648b074f180985690412e84405ccc7627ea54a6a00ddabcee386d4a7d9df677efa6c91c5f9fd2b83480f05d05f3e3a248fce9ea72978decdaa951acf458d553f83ceee8c42710b2370b8f4140942ed53e5ef3d2d6b571f009f925367b8c574319d5b72ebe4c98beca3ca2716dc209b0e0c7c49716e21df9959da15fb0f90612ec5c562684279989288742fc3ebbf50a1e6eb181eedcd5bd6324aafa66e0e43efb92bcccb59860ed1d9ff8241f85895eda646b7804c54d43730d95cc709ad87b347e19ff9ee668b11748f80d15446f6a9e74c112c45a81416c7dd73bc47d1836fed74991b53a4ef9b764cadf3bf55aef8fe76aafe492254db4b706b1176d732bdc412b534fd8d48ac443ef9ef9cc866408cbe64bf952b243e710aaf509f4b8d513fed40e5dc6ac48f3caec25591bcba9ab79fbbde859e6e72b916dd69efe6f07988c01410f0aa96517ede6439f58980093d15d3dfe80b9344664575f93a642fa6783064178eb97b87f45f5cf861b32911cacd7600f99680261a1f15134811ea5a53f1351eb2d96f3aef7c16cb68cce10a208a38c3dcac312cdd9703acb01d547edbedd7c6250cb1befdad4a6f5d77f9493523f5df17e650f399d8fd7872b236c41b067d4685cef0c5c2316fbe8041028180520a941f0b75681ebd088649b58f2b2c0e58dd95c1b94a896d80390203010001a3433041300f0603551d0f0101ff04050303070600301d0603551d0e041604147911c1fe9a71993f2d92b05fae6bd4c90b77eb59300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038202010007d4e55fd24764695e512e6cb0ae105198fa0fded720a1e160ae759d2893ba055b317c0c8caac5e3251e0dcf18b3299455cf170838edddeae6f50969f6a8832d5e4bec914874911720e04ac4bdc81e57cdaa02554a83b8bb5f4883af4a1b9609a15eaa28a23b0f185bcd8622c90dc4c7c6c3bf709a1e1537f7e9783eb892490486abbd89585f6febdb951776e36e1c8e2cb5b1d85eafee892095ce0a2fba127af7ba0f5d641ee625c1b9b620e1de20bf78eb11b9b3b3b186d669a941d60b33cf6fae61e004db678b8273e85dc7aebda97764e11792bf0a7996b676bfef29c2e8fee83f93b5d1521c7f21060e880c689b4b9b1eaf7f1719649b0ebb1ea9d224f86d238dfcb3c5c3b044be4fae8dd902def393966979ee33fd583508b6cda92b9488af2b8f2f21479f14b5cb8633ed822cc1116816d374d692e64deb870995e5b8fb3799adea3287ac1824d88e2b73ed45d27f5ccd92320d1310714df8b9e0d15019994301eb0c68e94d854c6e22ff399f83565b37770246083c7067982a9c5e90e42802747f7116c478b3c5e8525dfeecacd6238b8234555be0a4e2cb525d7fd39ed316160119ab8075989efa2f04ed34925951d33302ff1a476f35326631e66e2e3af4e87436c6a2922b028b0e5e0210c9eae77fb73032822e41e0d7c4ef35b6ea6af6bdfeb45419664c6210ef2278bce9c4fe78c8bd89cf0a70a6b5362e3355").unwrap();
        // certs.push(Certificate::from_der(&der).unwrap());
        // // let der = hex::decode("3082058930820471a00302010202100b0c6b2c466917b04773c647d4afc0c8300d06092a864886f70d01010c05003061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f74204732301e170d3235303532313030303030305a170d3239303631393233353935395a3051310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e31223020060355040313194d6963726f736f667420544c532052534120526f6f7420473230820222300d06092a864886f70d01010105000382020f003082020a0282020100dfea8b9f47e1281071af41d619db9257de6babe62edead3a6083b71398ac5bb9320b7beb9f72276b5d40abbe180693b20dd212edb874f57f2feaa81794f63316578ade207c21ddb7daacde4e64b05acd4b75f3ef02644ded52daa38f04e891f8d7fb3f19fd4e45395ee829c3d6f267afb30094c18de1f04a189839fac009843341050305abf475e153a521925c444ce66057a4900297c7d5d89304324aed8551edd6c5baa03f368a2f6f4c39a8046922843b7514f7d93eb4a9d0074138817e46481de819e670b8a0aa18dd72bf7e7db56c4e19701184041381d462fd9c6bf11cddffeca7e0e6c78d314bbff26b33ccd18cb6feb11ba34aa85f0e7f3176383f07476c01a8aca514da82b05f1f6cbc891ac0122acb7b971f282e31168a534c7566f97d01d6c260aa658f319e72cbcc9b2de544199357ab6e8ec2d92e65b0722de7a1c3a17e491d5967d609d418126dc0954578c9f1606ae4f6ee06243b734a5a11c23e9761c078eeef13a730e24a382dee58171320b7362adf0b32b4c238b191dd12b045b67cc0b11d62a19ddd71121596019d0a09f5b1ddb3d9e0384234f669b6c3af1673fed443f843e458f94fb3f3ecd63d943a403815ab0c86d064ce1a63e8849455095ab604b6d13e9a15c7641180d01b820e4dff459eb26507251fdb9ac8c6ecd65b8550049f1ccb5d2082679e79e2dfe8f2e86fc420723086e59d7527350203010001a382014b30820147300f0603551d130101ff040530030101ff301d0603551d0e04160414de918648b7a1315931f14b5f07a9dc8879daa876301f0603551d230418301680144e2254201895e6e36ee60ffafab912ed06178f39300e0603551d0f0101ff04040302018630130603551d25040c300a06082b06010505070301307606082b06010505070101046a3068302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304006082b060105050730028634687474703a2f2f636163657274732e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7447322e63727430420603551d1f043b30393037a035a0338631687474703a2f2f63726c332e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7447322e63726c30130603551d20040c300a3008060667810c010202300d06092a864886f70d01010c050003820101000bbcb42b3774c54ba7360236c6afe113cc8a9a971bfce3448cee5400e5e4411a46f00b7634ff99556235aaad8a9c0c5a62cc43c0cbea4a1dbd6b1dafb11925669cf7796e5b2580248185c7792d355f420978ed9fe265d5c4205082108f6a3aed188e4889aba609f8e180fc06751627255a8fb83a706c1847f063f4530ed9153520f3913d1301a0e2fa2408455677d167a93142d057ff1a26bec543d857a963ffaff33ad8f67b4b10a297a1cf66be676709f9b54ce7ab192bbf223d7ddec6f7ef63382cdd56c4f90952dadfe3886fd56d6bf708412f8e3e86319ff17c4af5d661a4464628ef57bab06f92d8d27725ed7ba629ce3b727911d4e0a7546d352ba47a").unwrap();
        // // certs.push(Certificate::from_der(&der).unwrap());
        // // let cert=Certificate::from_der(&der).unwrap();
        // // cert.get_aia().unwrap();
        // ROOT_STORES.verify_cert(&certs, "cn.bing.com").unwrap();

        // let key = RsaKey::gen_new_key(2048).unwrap();
        // let sign = AlgorithmSigner::new_verify(certs[0].pub_key().unwrap(), &SignatureAlgorithm::RSA_PSS_RSAE_SHA256).unwrap();
        // let data = vec![250, 157, 99, 65, 250, 213, 178, 24, 145, 187, 33, 55, 120, 125, 226, 64, 166, 104, 26, 204, 2, 14, 116, 245, 219, 20, 34, 96, 209, 205, 246, 159, 3, 0, 24, 97, 4, 3, 185, 231, 132, 27, 197, 188, 183, 38, 148, 144, 192, 191, 92, 232, 18, 28, 147, 155, 200, 183, 61, 58, 195, 152, 38, 1, 127, 56, 117, 214, 207, 170, 105, 74, 225, 113, 153, 238, 19, 115, 167, 188, 81, 89, 200, 128, 63, 133, 48, 167, 213, 54, 204, 250, 168, 172, 118, 132, 61, 167, 76, 164, 58, 138, 37, 90, 52, 235, 33, 240, 5, 23, 60, 211, 126, 212, 154, 253, 147, 66, 49, 115, 0, 29, 81, 90, 117, 159, 164, 195, 245, 9, 37, 164, 248];
        // let signature = hex::decode("3022a6e66296517c7629822d631e2631402209cbdff8d57663fb47dfc6154f04c02a55f031c7ab3865aa23405000f2313a0bb3baddf3d2f0e66da3026e2317b9b0cf96eb4f47af9d437e16218ecf2af90d336c3ae6c6e6a93d2ca40c58dead5bacc45a3edb584260949401f007ab77c022893ba178452d82da34ee4b1fc3453b689c76f2a33bc5cce5c6b3d0bcfdbafa94ff5d06d2d3ad447c6628f48145e87dc406806e98e9e20565f64ca14fd8707de3f29a6839988757b523d953c0fff74cb67f7000b04b10fb550c241dbf343125258fc6852707b330622ac0cfafd102a0882c8de271f3fc05ad256ce07505d5c06dc7eda6985bf9e79fd26c4bcfefb564").unwrap();
        // sign.verify(data, &signature).unwrap();
        // let sign = sign.sign("data").unwrap();
        // println!("{} {:x?}", sign.len(), sign);
    }
}