use crate::export::{check_run, handle_err1};
use crate::{json, Fingerprint, H2Finger, H2Setting};
use reqtls::{Bytes, CompressionMethod, EcPointFormat, Extension, ExtensionType, ExtensionValue, NamedCurve, SignatureAlgorithm, TlsFinger, Version, ALPN};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::slice;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_ja3(ja3: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let ja3 = unsafe { CStr::from_ptr(ja3) }.to_str()?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_ja3(ja3, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_ja4(ja4: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let ja4 = unsafe { CStr::from_ptr(ja4) }.to_str()?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_ja4(ja4, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_from_client_hello(client_hello: *const u8, len: usize, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let client_hello = unsafe { slice::from_raw_parts(client_hello, len) }.to_vec();
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::from_client_hello(client_hello, token)?)))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_random(token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        Ok(Box::into_raw(Box::new(Fingerprint::random(token))))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Fingerprint_custom(custom: *const c_char, token: *const c_char, err: *mut *mut c_char) -> *mut Fingerprint {
    check_run(move || {
        let custom = json::from_bytes(unsafe { CStr::from_ptr(custom) }.to_bytes())?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let mut extensions = vec![];
        for (key, value) in custom["extensions"].entries() {
            let typ = ExtensionType::new(key.parse().or(Err("Invalid extend type"))?);
            match typ.as_u16() {
                ExtensionType::SignatureAlgorithms if !value.is_null() => {
                    let values: Vec<SignatureAlgorithm> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::Algorithms(values)));
                }
                ExtensionType::CompressionCertificate if !value.is_null() => {
                    let values: Vec<CompressionMethod> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::CompressionMethods(values)));
                }
                ExtensionType::EcPointFormats if !value.is_null() => {
                    let values: Vec<EcPointFormat> = value.members().map(|x| x.as_u8().unwrap_or(0).into()).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::EcPointFormats(values)));
                }
                ExtensionType::SupportedVersions if !value.is_null() => {
                    let values: Vec<Version> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::SupportedVersions(values)));
                }
                ExtensionType::SupportedGroup | ExtensionType::KeyShare if !value.is_null() => {
                    let values: Vec<NamedCurve> = value.members().map(|x| x.as_u16().unwrap_or(0).into()).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::Curves(values)));
                }
                ExtensionType::ApplicationLayerProtocolNegotiation | ExtensionType::ApplicationSetting | ExtensionType::ApplicationSettingOld if !value.is_null() => {
                    let values = value.members().map(|x| ALPN::from_slice(x.as_str().unwrap_or("").as_bytes())).collect();
                    extensions.push(Extension::new(typ, ExtensionValue::Alps(values)))
                }
                ExtensionType::Padding if !value.is_null() => {
                    let value=value.as_usize().unwrap_or(0);
                    extensions.push(Extension::new(typ, ExtensionValue::Padding(value)));
                }
                _ => match typ.is_reserved() && !value.is_null() {
                    true => {
                        let value = value.members().map(|x| x.as_u8().unwrap_or(0)).collect();
                        extensions.push(Extension::new(typ, ExtensionValue::Bytes(Bytes::new(value))))
                    }
                    false => extensions.push(Extension::new_default(typ))
                }
            }
        }


        let tls = TlsFinger::Custom {
            suites: custom["suites"].members().map(|x| x.as_u16().unwrap_or(0).into()).collect(),
            extensions,
        };
        println!("{:#?}", tls);
        let mut h2 = H2Finger {
            setting: vec![],
            window_size: custom["window_size"].as_u32().or(Err("missing window_size"))?,
            weight: custom["weight"].as_u8().unwrap_or(0),
            priority: custom["priority"].as_bool().unwrap_or(false),
        };
        for (key, value) in custom["settings"].entries() {
            match key {
                "HeaderTableSize" => h2.setting.push(H2Setting::HeaderTableSize(value.as_u32()?)),
                "EnablePush" => h2.setting.push(H2Setting::EnablePush(value.as_u32()?)),
                "MaxConcurrentStreams" => h2.setting.push(H2Setting::MaxConcurrentStreams(value.as_u32()?)),
                "InitialWindowSize" => h2.setting.push(H2Setting::InitialWindowSize(value.as_u32()?)),
                "MaxFrameSize" => h2.setting.push(H2Setting::MaxFrameSize(value.as_u32()?)),
                "MaxHeaderListSize" => h2.setting.push(H2Setting::MaxHeaderListSize(value.as_u32()?)),
                "Reserved" => h2.setting.push(H2Setting::Reserved { flag: value["flag"].as_u16()?, value: value["value"].as_u32()? }),
                _ => return Err("unknown setting type".into()),
            }
        }
        let finger = Fingerprint::new(tls, h2, token)?;
        Ok(Box::into_raw(Box::new(finger)))
    }, |e| handle_err1(e, err, null_mut()))
}


