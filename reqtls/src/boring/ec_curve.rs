use super::bindings::*;
use super::*;
use crate::buffer::BufPtr;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;
use std::ffi::c_void;
use std::ptr::null_mut;

pub struct EcCurve {
    ec_key: CPointer<EC_KEY>,
}

impl EcCurve {
    pub fn new_p256() -> RlsResult<EcCurve> {
        EcCurve::new(NID_X9_62_prime256v1)
    }

    pub fn new_p384() -> RlsResult<EcCurve> {
        EcCurve::new(NID_secp384r1)
    }

    pub fn new_p521() -> RlsResult<EcCurve> {
        EcCurve::new(NID_secp521r1)
    }
    fn new(nid: i32) -> RlsResult<EcCurve> {
        let ec_key = CPointer::new_checked(unsafe { EC_KEY_new_by_curve_name(nid) }, RlsError::InitEcKeyError)?;
        unsafe { EC_KEY_generate_key(ec_key.as_mut_ptr()) }.ok(RlsError::GenEcKeyError)?;
        Ok(EcCurve {
            ec_key,
        })
    }

    pub fn pub_key(&self) -> RlsResult<BufPtr> {
        let pub_key = unsafe { EC_KEY_get0_public_key(self.ec_key.as_ptr()) };
        let group = unsafe { EC_KEY_get0_group(self.ec_key.as_ptr()) };
        let mut buf = BufPtr::nullptr();
        let len = unsafe {
            EC_POINT_point2buf(
                group,
                pub_key,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                buf.ptr_mut(),
                null_mut(),
            )
        };
        buf.check_ptr(len)?;
        Ok(buf)
    }

    pub fn diffie_hellman(&self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        let group = unsafe { EC_KEY_get0_group(self.ec_key.as_ptr()) };
        let server_point = CPointer::new_checked(unsafe { EC_POINT_new(group) }, RlsError::InitEcPointError)?;
        unsafe {
            EC_POINT_oct2point(
                group,
                server_point.as_mut_ptr(),
                pub_key.as_ref().as_ptr(),
                pub_key.as_ref().len(),
                null_mut(),
            )
        }.ok(RlsError::OCT2PointError)?;
        let secret_len = unsafe { EC_GROUP_get_degree(group) }.div_ceil(8);
        let mut secret = vec![0u8; secret_len as usize];
        let ret = unsafe {
            ECDH_compute_key(
                secret.as_mut_ptr() as *mut c_void,
                secret_len as usize,
                server_point.as_ptr(),
                self.ec_key.as_ptr(),
                None,
            )
        };
        if ret <= 0 {
            return Err(RlsError::ComputeKeyError);
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::ec_curve::EcCurve;

    #[test]
    fn test_p256() {
        let p256 = EcCurve::new_p256().unwrap();
        let pub_key = p256.pub_key().unwrap();
        println!("{} {:?}", pub_key.len(), pub_key);
        let secret = p256.diffie_hellman([4, 110, 171, 17, 103, 44, 250, 48, 210, 161, 85, 216, 127, 10, 52, 255, 211, 240, 251, 75, 89, 62, 84, 18, 225, 201, 112, 116, 175, 165, 155, 199, 174, 228, 14, 37, 218, 134, 139, 14, 190, 180, 212, 111, 110, 52, 185, 10, 120, 166, 16, 41, 158, 214, 61, 214, 61, 21, 131, 58, 145, 109, 154, 252, 129]).unwrap();
        println!("secret: {} {:?}", secret.len(), secret);

        let p384 = EcCurve::new_p384().unwrap();
        let pub_key = p384.pub_key().unwrap();
        println!("{} {:?}", pub_key.len(), pub_key);
        let secret = p384.diffie_hellman([4, 116, 241, 106, 68, 192, 211, 181, 90, 52, 63, 53, 216, 172, 182, 210, 32, 17, 251, 40, 178, 12, 112, 118, 136, 140, 243, 117, 129, 83, 164, 223, 161, 80, 227, 167, 66, 202, 107, 115, 221, 217, 42, 10, 188, 64, 47, 61, 142, 73, 218, 130, 136, 106, 212, 37, 196, 135, 232, 182, 119, 159, 106, 99, 135, 107, 171, 108, 100, 79, 198, 12, 152, 70, 138, 72, 6, 152, 137, 218, 10, 128, 141, 200, 89, 21, 56, 247, 114, 61, 204, 251, 23, 46, 172, 193, 229]).unwrap();
        println!("secret: {} {:?}", secret.len(), secret);

        let p521 = EcCurve::new_p521().unwrap();
        let pub_key = p521.pub_key().unwrap();
        println!("{} {:?}", pub_key.len(), pub_key);
        let secret = p521.diffie_hellman([4, 1, 228, 222, 12, 162, 233, 210, 208, 64, 245, 237, 32, 110, 181, 171, 234, 51, 29, 190, 116, 248, 250, 213, 193, 183, 10, 90, 238, 170, 189, 6, 147, 216, 109, 237, 131, 250, 213, 103, 11, 216, 185, 243, 43, 254, 45, 24, 15, 140, 45, 252, 58, 101, 13, 128, 160, 161, 44, 99, 209, 107, 222, 250, 1, 154, 129, 1, 119, 124, 152, 204, 29, 235, 24, 160, 212, 245, 164, 71, 182, 153, 229, 248, 182, 249, 82, 127, 253, 166, 251, 82, 213, 217, 179, 158, 161, 25, 133, 22, 169, 179, 8, 0, 146, 119, 70, 209, 113, 114, 192, 196, 69, 155, 195, 131, 149, 146, 170, 24, 149, 49, 210, 127, 129, 97, 206, 183, 250, 16, 13, 180, 196]).unwrap();
        println!("secret: {} {:?}", secret.len(), secret);
    }
}