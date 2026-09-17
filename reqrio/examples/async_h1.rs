use reqrio::*;
use std::fmt::{Debug, Formatter};
use std::os::raw::{c_int, c_void};
use std::ptr::{null, null_mut};
use std::string::ToString;
use std::{fs, slice};

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[cfg(feature = "log")]
fn test_log() {
    set_logger(&LOGER).unwrap();
    set_max_level(LevelFilter::Trace);
}


#[repr(C)]
struct KeyShare {
    len: u16,
    ptr: *const c_void,
}

impl KeyShare {
    pub fn new(entries: &[KeyEntry]) -> KeyShare {
        KeyShare {
            len: entries.len() as u16,
            ptr: entries.as_ptr() as *const c_void,
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for KeyShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("KeyShare");
        struct_debug.field("len", &self.len);
        let mut entries = vec![];
        let mut reader = Reader::from_ptr(self.ptr as *const u8, self.len as usize);
        while reader.position() < reader.size() {
            let mut entry = KeyEntry::default();
            unsafe { KeyEntry_parse(&mut reader, &mut entry) };
            entries.push(entry);
        }
        struct_debug.field("entries", &entries);
        struct_debug.finish()
    }
}

#[repr(C)]
struct SupportedGroups {
    len: u16,
    ptr: *const c_void,
}

impl SupportedGroups {
    pub const fn new(groups: &[NamedCurve]) -> SupportedGroups {
        SupportedGroups {
            len: groups.len() as u16,
            ptr: groups.as_ptr() as *const c_void,
        }
    }
}

#[repr(C)]
#[derive(Default)]
#[cfg_attr(debug_assertions, derive(Debug))]
struct StatusRequest {
    typ: u8,
    resp_id_len: u16,
    req_ext_len: u16,
}

impl StatusRequest {
    pub const OCSP: StatusRequest = StatusRequest { typ: 1, resp_id_len: 0, req_ext_len: 0 };
}


#[repr(C)]
#[derive(PartialEq, Copy, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
struct ExtensionType(u16);
#[allow(non_upper_case_globals)]
impl ExtensionType {
    const ServerName: ExtensionType = ExtensionType(0x0);
    const StatusRequest: ExtensionType = ExtensionType(0x5);
    const SupportedGroup: ExtensionType = ExtensionType(0xa);
    const EcPointFormats: ExtensionType = ExtensionType(0xb);
    const SignatureAlgorithms: ExtensionType = ExtensionType(0xd);
    const ApplicationLayerProtocolNegotiation: ExtensionType = ExtensionType(0x10);
    const SignedCertificateTimestamp: ExtensionType = ExtensionType(0x12);
    const Padding: ExtensionType = ExtensionType(0x15);
    const EncryptTheMac: ExtensionType = ExtensionType(0x16);
    const ExtendMasterSecret: ExtensionType = ExtensionType(0x17);
    const SessionTicket: ExtensionType = ExtensionType(0x23);
    const CompressionCertificate: ExtensionType = ExtensionType(0x1b);
    const SupportedVersions: ExtensionType = ExtensionType(0x2b);
    const PskKeyExchangeMode: ExtensionType = ExtensionType(0x2d);
    const PostHandshakeAuth: ExtensionType = ExtensionType(0x31);
    const KeyShare: ExtensionType = ExtensionType(0x33);
    const RenegotiationInfo: ExtensionType = ExtensionType(0xff01);
    const EncryptedClientHello: ExtensionType = ExtensionType(0xfe0d);
    const ApplicationSetting: ExtensionType = ExtensionType(0x44cd);
    const PreSharedKey: ExtensionType = ExtensionType(0x29);
    const ApplicationSettingOld: ExtensionType = ExtensionType(0x4469);
    const QuicTrpParameters: ExtensionType = ExtensionType(0x0039);

    pub fn spec(&self) -> &str {
        match self.0 {
            0 => "ServerName",
            5 => "StatusRequest",
            0xa => "SupportedGroup",
            0xb => "EcPointFormats",
            0xd => "SignatureAlgorithms",
            0x10 => "ApplicationLayerProtocolNegotiation",
            0x12 => "SignedCertificateTimestamp",
            0x15 => "Padding",
            0x16 => "EncryptTheMac",
            0x17 => "ExtendMasterSecret",
            0x23 => "SessionTicket",
            0x1b => "CompressionCertificate",
            0x2b => "SupportedVersions",
            0x2d => "PskKeyExchangeMode",
            0x31 => "PostHandshakeAuth",
            0x33 => "KeyShare",
            0xff01 => "RenegotiationInfo",
            0xfe0d => "EncryptedClientHello",
            0x44cd => "ApplicationSetting",
            0x29 => "PreSharedKey",
            0x4469 => "ApplicationSettingOld",
            0x0039 => "QuicTrpParameters",
            _ => "Reversed"
        }
    }
}

#[repr(C)]
struct Extension {
    typ: ExtensionType,
    len: u16,
    value: *const c_void,
}

impl Extension {
    pub const fn new<T: ?Sized>(typ: ExtensionType, len: u16, value: &T) -> Extension {
        Extension {
            typ,
            len,
            value: value as *const T as *mut c_void,
        }
    }

    pub const fn new_null(typ: ExtensionType) -> Extension {
        Extension {
            typ,
            len: 0,
            value: null(),
        }
    }

    pub const fn new_slice<T>(typ: ExtensionType, slice: &[T]) -> Extension {
        Extension {
            typ,
            len: slice.len() as u16,
            value: slice.as_ptr() as *const c_void,
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("Extension");
        debug_struct.field("type", &self.typ);
        debug_struct.field("len", &self.len);
        let mut reader = Reader::from_ptr(self.value as *const u8, self.len as usize);
        match self.typ {
            ExtensionType::ServerName => {
                let mut reader = Reader::from_ptr(self.value as *const u8, self.len as usize);
                let list_len = reader.read_u16().unwrap() as usize;
                debug_struct.field("list_len", &list_len);
                let mut server_names = vec![];
                while reader.position() < reader.size() {
                    let mut server_name = ServerName::default();
                    unsafe { ServerName_parse(&mut reader, &mut server_name) };
                    server_names.push(server_name);
                }
                debug_struct.field("server_name", &server_names);
            }
            ExtensionType::StatusRequest => {
                let mut status_request = StatusRequest::default();
                unsafe { StatusRequest_parse(&mut reader, &mut status_request) };
                debug_struct.field("status_requests", &status_request);
            }
            ExtensionType::Padding => {
                debug_struct.field("value", &self.len);
            }
            ExtensionType::KeyShare => {
                let mut key_share = KeyShare { len: 0, ptr: null() };
                unsafe { KeyShare_parse(&mut reader, &mut key_share) };
                debug_struct.field("key_share", &key_share);
            }
            ExtensionType::SignatureAlgorithms => {
                let mut reader = Reader::from_ptr(self.value as *const u8, self.len as usize);
                let len = reader.read_u16().unwrap();
                debug_struct.field("list_len", &len);
                let mut reader = reader.read_reader(len as usize).unwrap();
                let mut algorithms = vec![];
                while reader.position() < reader.size() {
                    algorithms.push(SignatureAlgorithm::new(reader.read_u16().unwrap()))
                }
                debug_struct.field("algorithms", &algorithms);
            }
            _ => {}
        }
        debug_struct.finish()
    }
}

#[repr(C)]
#[derive(Default)]
struct ClientHello {
    len: u24,
    ver: u16,
    random: *const u8,
    session_id_len: u8,
    session_id: *const u8,
    suite_len: u16,
    suites: *const u8,
    comp_method_len: u8,
    comp_method: *const u8,
    ext_len: u16,
    extension: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for ClientHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ClientHello");
        debug_struct.field("len", &self.len);
        debug_struct.field("ver", &Version::new(self.ver));
        let random = hex::encode(unsafe { slice::from_raw_parts(self.random, 32) });
        debug_struct.field("random", &random);
        debug_struct.field("session_id_len", &self.session_id_len);
        let session_id = hex::encode(unsafe { slice::from_raw_parts(self.session_id, self.session_id_len as usize) });
        debug_struct.field("session_id", &session_id);
        debug_struct.field("suite_len", &self.suite_len);
        let suites = unsafe { slice::from_raw_parts(self.suites, self.suite_len as usize) };
        let suites = suites.chunks(2).map(|chunk| {
            let suite = u16::from_be_bytes([chunk[0], chunk[1]]);
            CipherSuite::from(suite)
        }).collect::<Vec<_>>();
        debug_struct.field("suites", &suites);
        debug_struct.field("comp_method_len", &self.comp_method_len);
        let comp_methods = hex::encode(unsafe { slice::from_raw_parts(self.comp_method, self.comp_method_len as usize) });
        debug_struct.field("comp_method", &comp_methods);
        debug_struct.field("ext_len", &self.ext_len);
        let mut reader = Reader::from_ptr(self.extension, self.ext_len as usize);
        let mut extensions = vec![];
        while reader.position() < reader.size() {
            let mut extension = Extension { typ: ExtensionType::Padding, len: 0, value: null_mut() };
            unsafe { Extension_parse(&mut reader, &mut extension) };
            extensions.push(extension);
        }
        debug_struct.field("extensions", &extensions);
        debug_struct.finish()
    }
}


#[repr(C)]
#[derive(Default)]
struct HandShake {
    typ: u8,
    len: usize,
    ptr: *const u8,
}

impl HandShake {
    pub fn client_hello(&self) -> ClientHello {
        let mut client_hello = ClientHello::default();
        unsafe { ClientHello_parse(&mut Reader::from_ptr(self.ptr, usize::MAX), &mut client_hello) };
        client_hello
    }
}

#[cfg(debug_assertions)]
impl Debug for HandShake {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("HandShake");
        let typ = HandshakeType::from_byte(self.typ).unwrap_or(HandshakeType::Finish);
        debug_struct.field("typ", &typ);
        debug_struct.field("len", &self.len);
        match typ {
            HandshakeType::ClientHello => {
                debug_struct.field("client_hello", &self.client_hello());
            }
            HandshakeType::ClientKeyExchange => {
                // debug_struct.field("client_key_exchange", unsafe { self.parsed.client_key_exchange.deref() });
            }
            _ => {}
        }
        debug_struct.finish()
    }
}

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
struct Alert {
    level: u8,
    desc: u8,
}


#[repr(C)]
#[derive(Default)]
struct Record {
    typ: u8,
    ver: u16,
    len: u16,
    message: *const u8,
}


#[cfg(debug_assertions)]
impl Debug for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("Record");
        let typ = RecordType::from_byte(self.typ).unwrap_or(RecordType::HandShake);
        struct_debug.field("typ", &typ);
        struct_debug.field("ver", &Version::new(self.ver));
        struct_debug.field("len", &self.len);
        match typ {
            RecordType::CipherSpec => {
                struct_debug.field("message", &"CipherSpec");
            }
            RecordType::Alert => {}
            RecordType::HandShake => {
                let mut messages = vec![];
                let mut reader = Reader::from_ptr(self.message, self.len as usize);
                while reader.position() < reader.size() {
                    let mut message = HandShake::default();
                    unsafe { HandShake_parse(&mut reader, &mut message) };
                    messages.push(message);
                }
                struct_debug.field("messages", &messages);
            }
            RecordType::ApplicationData => {}
        }
        struct_debug.finish()
    }
}

#[repr(C)]
enum KeyExchangeAlg {
    ExchangeAlg_None = 0,
    ExchangeAlg_ECDHE_ECDSA = 1,
    ExchangeAlg_ECDHE_RSA = 2,
    ExchangeAlg_DHE_DSS = 3,
    ExchangeAlg_DHE_RSA = 4,
    ExchangeAlg_DH_ANON = 5,
    ExchangeAlg_DH_DSS = 6,
    ExchangeAlg_DH_RSA = 7,
    ExchangeAlg_RSA = 8,
    ExchangeAlg_ECC = 9,
}

unsafe extern "C" {
    fn Record_parse(reader: *mut Reader, record: *mut Record) -> c_int;
    fn HandShake_parse(reader: *mut Reader, handshake: *mut HandShake) -> c_int;
    fn ClientHello_parse(reader: *mut Reader, client_hello: *mut ClientHello) -> c_int;
    fn Extension_parse(reader: *mut Reader, extension: *mut Extension) -> c_int;
    fn ServerName_parse(reader: *mut Reader, server_name: *mut ServerName) -> c_int;
    fn StatusRequest_parse(reader: *mut Reader, extension: *mut StatusRequest) -> c_int;
    fn KeyShare_parse(reader: *mut Reader, key_share: *mut KeyShare) -> c_int;
    fn KeyEntry_parse(reader: *mut Reader, key_entry: *mut KeyEntry) -> c_int;
    fn Record_build(
        writer: *mut Writer,
        typ: u8,
        connection: *mut Connection,
        config: *const ClientConfig,
    ) -> c_int;
    fn Record_build_client_hello(
        writer: *mut Writer,
        connection: *mut Connection,
        config: *const ClientConfig,
        record_version: u16,
        reader: *mut Reader,
    ) -> c_int;
    fn Record_build_custom(
        writer: *mut Writer,
        connection: *mut Connection,
        config: *const ClientConfig,
        record_version: Version,
        suite_count: usize,
        suites: *const u16,
        message_version: Version,
        ext_count: usize,
        extensions: *const Extension,
    ) -> c_int;
}


enum TlsFinger {
    Custom {
        ///record layer version
        record_version: Version,
        ///handshake message version
        message_version: Version,
        ///cipher suites
        suites: Vec<CipherSuite>,
        ///extension
        extensions: Vec<ExtendValue>,
    }
}

#[repr(C)]
struct ClientConfig {
    sni_len: u16,
    sni: *const u8,
    verify: bool,
    key_log: *const u8,
    alpn: ALPN,
    version: u16,
}

const DEFAULT_TLS: [u8; 1815] = [22, 3, 1, 7, 18, 1, 0, 7, 14, 3, 3, 72, 133, 60, 49, 150, 191, 27, 170, 23, 106, 202, 192, 176, 254, 96, 142, 56, 79, 100, 164, 140, 185, 209, 110, 177, 124, 82, 223, 185, 167, 59, 211, 32, 26, 94, 33, 117, 55, 188, 58, 243, 227, 20, 228, 216, 150, 57, 186, 118, 206, 37, 17, 64, 9, 220, 44, 34, 53, 102, 7, 48, 196, 227, 137, 154, 0, 32, 218, 218, 19, 1, 19, 2, 19, 3, 192, 43, 192, 47, 192, 44, 192, 48, 204, 169, 204, 168, 192, 19, 192, 20, 0, 156, 0, 157, 0, 47, 0, 53, 1, 0, 6, 165, 26, 26, 0, 0, 0, 45, 0, 2, 1, 1, 0, 11, 0, 2, 1, 0, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 51, 4, 239, 4, 237, 250, 250, 0, 1, 0, 17, 236, 4, 192, 195, 153, 180, 75, 128, 46, 167, 137, 131, 30, 38, 37, 235, 214, 138, 19, 107, 113, 62, 128, 165, 2, 51, 162, 45, 188, 128, 2, 166, 170, 176, 123, 163, 175, 217, 53, 226, 243, 21, 221, 183, 45, 250, 74, 148, 247, 90, 116, 148, 218, 117, 155, 3, 120, 15, 85, 138, 61, 10, 6, 8, 163, 141, 138, 242, 18, 45, 28, 204, 163, 169, 18, 27, 83, 135, 233, 218, 70, 217, 19, 181, 57, 176, 201, 214, 180, 166, 138, 154, 21, 248, 37, 137, 43, 38, 206, 112, 129, 91, 21, 154, 125, 238, 119, 171, 126, 165, 180, 253, 48, 185, 242, 2, 129, 139, 166, 199, 85, 26, 101, 240, 17, 101, 67, 7, 179, 52, 113, 110, 102, 118, 81, 196, 231, 162, 165, 225, 79, 244, 59, 39, 31, 230, 39, 39, 50, 70, 38, 134, 40, 21, 123, 100, 26, 98, 117, 30, 48, 178, 99, 101, 127, 22, 8, 104, 216, 215, 184, 9, 84, 57, 217, 121, 65, 117, 152, 116, 148, 60, 106, 18, 218, 146, 183, 209, 70, 228, 232, 112, 164, 233, 5, 65, 162, 59, 124, 90, 177, 198, 68, 143, 113, 136, 86, 58, 9, 124, 95, 120, 163, 73, 7, 55, 55, 215, 163, 124, 219, 8, 188, 176, 156, 166, 220, 49, 180, 34, 146, 96, 216, 138, 147, 199, 169, 72, 65, 30, 125, 163, 179, 9, 196, 25, 135, 119, 27, 248, 199, 17, 81, 170, 155, 196, 54, 159, 21, 21, 70, 53, 135, 196, 35, 135, 187, 72, 197, 40, 70, 73, 27, 29, 146, 39, 192, 104, 111, 161, 84, 146, 70, 244, 68, 36, 170, 37, 142, 68, 59, 67, 16, 150, 236, 44, 205, 55, 122, 136, 226, 76, 152, 34, 146, 54, 250, 1, 107, 171, 129, 84, 102, 196, 14, 234, 225, 52, 202, 119, 112, 67, 72, 162, 182, 98, 124, 190, 213, 81, 209, 234, 13, 175, 99, 82, 6, 212, 37, 246, 0, 199, 62, 220, 75, 152, 192, 43, 223, 11, 94, 252, 123, 115, 206, 117, 162, 146, 64, 67, 226, 67, 108, 148, 71, 113, 99, 2, 89, 240, 81, 107, 48, 181, 41, 166, 64, 98, 179, 9, 141, 200, 52, 56, 82, 229, 152, 136, 124, 136, 219, 170, 11, 44, 112, 155, 26, 88, 148, 25, 22, 186, 78, 219, 156, 174, 201, 14, 182, 249, 48, 249, 218, 92, 181, 139, 184, 85, 134, 43, 89, 38, 62, 237, 163, 29, 42, 6, 168, 151, 99, 184, 56, 209, 15, 106, 12, 49, 153, 193, 177, 11, 204, 157, 21, 73, 176, 232, 96, 161, 240, 144, 22, 152, 195, 80, 183, 235, 94, 134, 16, 79, 246, 49, 54, 31, 214, 190, 236, 44, 119, 128, 99, 98, 131, 60, 46, 250, 48, 99, 129, 12, 134, 250, 167, 181, 171, 146, 56, 158, 171, 37, 131, 32, 38, 95, 178, 63, 13, 122, 43, 58, 154, 173, 3, 201, 70, 4, 203, 67, 213, 50, 55, 99, 20, 178, 232, 212, 207, 237, 218, 54, 181, 120, 181, 144, 230, 20, 110, 161, 140, 104, 71, 160, 86, 156, 131, 24, 166, 134, 32, 242, 148, 233, 217, 135, 93, 1, 69, 73, 105, 91, 211, 202, 104, 196, 48, 87, 112, 146, 163, 117, 172, 58, 55, 32, 58, 3, 54, 193, 225, 52, 180, 90, 242, 84, 139, 204, 200, 206, 7, 94, 78, 116, 163, 112, 241, 109, 75, 203, 201, 12, 140, 180, 46, 208, 155, 93, 208, 92, 98, 5, 40, 217, 218, 198, 104, 51, 188, 2, 231, 115, 73, 103, 198, 167, 204, 75, 235, 233, 91, 133, 215, 39, 91, 151, 108, 154, 192, 153, 126, 178, 100, 160, 166, 132, 212, 39, 149, 18, 5, 74, 50, 88, 163, 158, 96, 79, 30, 193, 72, 202, 33, 48, 210, 154, 26, 185, 43, 83, 193, 176, 171, 78, 227, 128, 95, 51, 146, 1, 233, 104, 132, 123, 120, 115, 145, 117, 253, 105, 81, 129, 183, 167, 206, 80, 11, 211, 26, 6, 133, 146, 110, 4, 213, 206, 109, 43, 97, 40, 69, 186, 104, 211, 159, 97, 124, 33, 175, 167, 95, 38, 188, 169, 92, 23, 80, 118, 152, 175, 40, 12, 12, 95, 33, 137, 10, 183, 138, 142, 86, 177, 233, 69, 9, 178, 38, 6, 102, 36, 167, 198, 112, 28, 58, 228, 97, 197, 65, 97, 231, 213, 118, 2, 121, 172, 193, 103, 204, 1, 144, 139, 125, 74, 25, 87, 100, 89, 233, 182, 39, 108, 226, 199, 145, 153, 8, 81, 251, 159, 139, 25, 124, 240, 201, 109, 225, 251, 97, 205, 28, 19, 194, 34, 197, 25, 65, 130, 237, 196, 105, 94, 41, 93, 84, 165, 6, 250, 9, 176, 136, 17, 105, 166, 243, 42, 138, 252, 10, 205, 86, 68, 135, 107, 94, 105, 129, 5, 243, 106, 86, 161, 106, 175, 73, 4, 30, 163, 74, 146, 97, 153, 105, 185, 131, 2, 93, 88, 94, 230, 241, 188, 250, 19, 30, 153, 84, 49, 178, 179, 166, 139, 81, 69, 52, 165, 153, 175, 28, 19, 173, 9, 93, 56, 203, 69, 138, 26, 138, 199, 245, 21, 36, 80, 49, 102, 166, 60, 246, 216, 150, 58, 168, 154, 32, 195, 112, 19, 152, 70, 114, 247, 154, 155, 225, 63, 147, 113, 157, 137, 231, 101, 168, 42, 71, 117, 213, 49, 179, 235, 203, 139, 76, 41, 53, 81, 11, 166, 167, 112, 188, 16, 168, 164, 236, 96, 240, 26, 154, 32, 37, 0, 80, 217, 108, 83, 84, 84, 245, 182, 155, 140, 248, 192, 12, 68, 121, 15, 57, 100, 161, 244, 178, 250, 188, 90, 133, 240, 97, 52, 140, 137, 227, 186, 23, 151, 192, 194, 107, 243, 187, 202, 215, 13, 147, 130, 47, 147, 42, 24, 202, 124, 160, 207, 134, 108, 107, 27, 77, 226, 87, 22, 6, 240, 30, 178, 229, 171, 59, 231, 25, 201, 19, 112, 242, 147, 99, 162, 24, 170, 207, 64, 40, 77, 198, 195, 197, 150, 113, 223, 75, 98, 213, 228, 78, 129, 3, 156, 52, 152, 36, 138, 118, 89, 240, 7, 73, 150, 83, 62, 128, 151, 160, 174, 227, 137, 166, 217, 174, 147, 100, 179, 166, 75, 207, 78, 87, 111, 103, 128, 43, 137, 148, 58, 224, 58, 36, 210, 119, 39, 38, 136, 127, 95, 200, 3, 147, 49, 17, 212, 170, 53, 218, 48, 167, 139, 86, 11, 180, 236, 45, 201, 24, 163, 153, 130, 129, 240, 70, 9, 63, 137, 121, 25, 7, 142, 189, 240, 94, 199, 247, 206, 3, 49, 26, 121, 188, 73, 203, 83, 115, 34, 232, 198, 166, 171, 190, 86, 165, 95, 110, 21, 85, 227, 132, 186, 111, 169, 196, 248, 224, 24, 157, 54, 80, 194, 106, 238, 103, 203, 231, 4, 215, 70, 80, 34, 194, 89, 182, 83, 67, 97, 101, 28, 155, 109, 113, 252, 152, 225, 143, 132, 255, 138, 161, 243, 232, 128, 188, 219, 216, 237, 221, 68, 14, 61, 126, 153, 88, 11, 217, 188, 127, 131, 244, 68, 218, 167, 97, 68, 44, 26, 98, 93, 197, 212, 77, 163, 97, 0, 29, 0, 32, 175, 160, 194, 30, 154, 179, 79, 17, 87, 50, 236, 184, 230, 181, 216, 51, 121, 196, 102, 8, 17, 115, 141, 139, 229, 96, 202, 253, 228, 70, 253, 11, 0, 0, 0, 14, 0, 12, 0, 0, 9, 51, 56, 104, 109, 122, 103, 46, 99, 110, 0, 43, 0, 7, 6, 74, 74, 3, 4, 3, 3, 0, 10, 0, 12, 0, 10, 250, 250, 17, 236, 0, 29, 0, 23, 0, 24, 0, 35, 0, 0, 0, 27, 0, 3, 2, 0, 2, 68, 105, 0, 5, 0, 3, 2, 104, 50, 0, 23, 0, 0, 254, 13, 1, 26, 0, 0, 1, 0, 1, 150, 0, 32, 203, 61, 233, 47, 49, 239, 207, 205, 90, 83, 199, 159, 190, 50, 0, 193, 244, 129, 227, 113, 153, 170, 41, 6, 73, 241, 171, 173, 110, 213, 3, 30, 0, 240, 220, 183, 36, 192, 65, 53, 109, 119, 236, 247, 207, 33, 54, 150, 238, 41, 27, 84, 158, 228, 139, 2, 130, 81, 214, 221, 222, 152, 101, 88, 110, 169, 151, 172, 208, 165, 33, 7, 153, 57, 95, 217, 104, 39, 56, 207, 96, 157, 217, 154, 156, 130, 158, 251, 197, 186, 131, 255, 194, 216, 147, 43, 85, 24, 134, 181, 193, 235, 193, 172, 18, 51, 39, 62, 92, 207, 232, 250, 30, 80, 251, 8, 18, 240, 95, 15, 203, 96, 118, 114, 169, 52, 199, 120, 172, 201, 152, 23, 61, 116, 110, 134, 114, 242, 170, 107, 96, 239, 166, 99, 105, 255, 215, 192, 59, 157, 125, 207, 63, 195, 240, 205, 178, 85, 52, 125, 131, 148, 218, 226, 38, 21, 177, 76, 95, 246, 38, 250, 142, 101, 181, 217, 50, 120, 218, 152, 15, 48, 127, 33, 175, 26, 18, 76, 171, 120, 219, 109, 65, 209, 207, 230, 157, 127, 26, 185, 0, 56, 247, 210, 9, 248, 94, 125, 125, 90, 208, 69, 162, 202, 72, 69, 105, 50, 13, 202, 227, 243, 59, 22, 57, 146, 240, 230, 130, 104, 137, 157, 61, 171, 219, 131, 243, 23, 127, 17, 95, 151, 209, 101, 186, 84, 94, 249, 193, 147, 161, 106, 188, 138, 211, 178, 77, 69, 138, 245, 68, 251, 85, 50, 24, 19, 110, 141, 250, 18, 48, 170, 0, 12, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 18, 0, 0, 0, 13, 0, 18, 0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 255, 1, 0, 1, 0, 234, 234, 0, 1, 0];


enum ExtendValue {
    KeyShare(Vec<KeyEntry>),
    StatusRequest(StatusRequest),
    ServerName(Vec<ServerName>),
    SupportedGroups(Vec<NamedCurve>),
    SupportedVersions(Vec<Version>),
    ApplicationLayerProtocolNegotiation(Vec<ALPN>),
    ApplicationSettings(Vec<ALPN>),
    ApplicationSettingOld(Vec<ALPN>),
    CompressionCertificate(Vec<CompressionMethod>),
    EcPointFormats(Vec<EcPointFormat>),
    PskKeyExchangeModes(Vec<PskMode>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    SessionTicket(Buf<'static>),
    EncryptedClientHello(Buf<'static>),
    ExtendedMasterSecret,
    SignedCertificateTimestamp,
    RenegotiationInfo(Buf<'static>),
    Reversed { typ: ExtensionType, value: Buf<'static> },
}

fn build_finger() -> TlsFinger {
    let finger = TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![
            CipherSuite::from(0x2a2a),
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        extensions: vec![
            ExtendValue::Reversed { typ: ExtensionType(0x2a2a), value: Buf::Ref(&[]) },
            ExtendValue::StatusRequest(StatusRequest::OCSP),
            ExtendValue::SupportedVersions(vec![
                Version::new(0x0a0a),
                Version::TLS_1_3,
                Version::TLS_1_2
            ]),
            ExtendValue::SessionTicket(Buf::Ref(&[])),
            ExtendValue::ExtendedMasterSecret,
            ExtendValue::EncryptedClientHello(Buf::Vec(hex::decode("0000010001e9002003f4432d9d68a1633d044fef75411c0143075011d1b8f5a85f78c343d0edf11b0090462702887383eff94e911d28c1fbe8f4327bc28f6e1cb5a1eef835666fbea10dd8137a39b4d115f0307ff08e8716fc3b1eb358d71763758a947eb5aa152f728def3c5809ca720b0b48e7d9bc8cb3ec490da5bc9cb1abf56c0e173dd9cc50b36a512da940dc1a59f05804d37795bd7991495b19db7680aecfb881964949896c4d884d177a55377e3cfdb1d9e8fe0470be").unwrap())),
            ExtendValue::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE]),
            ExtendValue::ApplicationSettings(vec![
                ALPN::HTTP20
            ]),
            ExtendValue::CompressionCertificate(vec![
                CompressionMethod::BROTLI
            ]),
            ExtendValue::ApplicationLayerProtocolNegotiation(vec![
                ALPN::HTTP20,
                ALPN::HTTP11
            ]),
            ExtendValue::SignatureAlgorithms(vec![
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm::RSA_PKCS1_SHA256,
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                SignatureAlgorithm::RSA_PKCS1_SHA384,
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
                SignatureAlgorithm::RSA_PKCS1_SHA512
            ]),
            ExtendValue::SignedCertificateTimestamp,
            ExtendValue::EcPointFormats(vec![
                EcPointFormat::UNCOMPRESSED
            ]),
            ExtendValue::ServerName(vec![ServerName::HOSTNAME]),
            ExtendValue::RenegotiationInfo(Buf::Ref(&[0])),
            ExtendValue::KeyShare(vec![
                KeyEntry::new(NamedCurve::new(REVERSED[rand::random::<usize>() % 16])),
                KeyEntry::X25519MLKEM768,
                KeyEntry::X25519,
            ]),
            ExtendValue::SupportedGroups(vec![
                NamedCurve::X25519MLKEM768,
                NamedCurve::X25519,
                NamedCurve::SecP256r1,
                NamedCurve::SecP384r1
            ]),
            ExtendValue::Reversed { typ: ExtensionType(0xdada), value: Buf::Ref(&[0]) }
        ],
    };
    return finger;
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    println!("{}", size_of::<ExtensionType>());
    let mut reader = Reader::from_slice(&DEFAULT_TLS);
    reader.read_u8().unwrap();
    reader.read_u16().unwrap();
    let len = reader.read_u16().unwrap() as usize;
    let mut reader = reader.read_reader(len).unwrap();
    let mut writer = Writer::with_capacity(4096);
    let mut connection = Connection::new_client(TlsSession::default(), None, false);
    let sni = "www.baidu.com";
    let config = ClientConfig {
        sni_len: sni.len() as u16,
        sni: sni.as_ptr(),
        verify: false,
        key_log: null(),
        alpn: ALPN::HTTP11,
        version: 0,
    };
    let ret = unsafe { Record_build_client_hello(&mut writer, &mut connection, &config, Version::TLS_1_0.into_inner(), &mut reader) };
    assert_eq!(ret, 1);
    assert!(RecordLayer::from_bytes(writer.filled(), reqtls::KeyExchangeAlg::NULL, false).is_ok());
    println!("{} {:?}", ret, writer.filled());
    writer.reset();
    let ret = unsafe { Record_build(&mut writer, HandshakeType::ClientHello as u8, &mut connection, &config) };
    println!("{} {} {:?}", ret, writer.len(), writer.filled());

    assert!(RecordLayer::from_bytes(writer.filled(), reqtls::KeyExchangeAlg::NULL, false).is_ok());
    let finger = build_finger();
    writer.reset();
    let TlsFinger::Custom {
        suites,
        record_version,
        message_version,
        extensions,
    } = &finger;
    let suites = suites.iter().map(|x| x.value()).collect::<Vec<_>>();
    let mut extends = Vec::with_capacity(extensions.len());
    for extension in extensions {
        extends.push(match extension {
            ExtendValue::KeyShare(entries) => Extension::new(ExtensionType::KeyShare, entries.len() as u16, entries.as_slice()),
            ExtendValue::StatusRequest(status_request) => Extension::new(ExtensionType::StatusRequest, 1, status_request),
            ExtendValue::ServerName(server_name) => Extension::new_slice(ExtensionType::ServerName, server_name.as_slice()),
            ExtendValue::SupportedGroups(groups) => Extension::new_slice(ExtensionType::SupportedGroup, groups.as_slice()),
            ExtendValue::SupportedVersions(versions) => Extension::new_slice(ExtensionType::SupportedVersions, versions.as_slice()),
            ExtendValue::ApplicationLayerProtocolNegotiation(alps) => Extension::new_slice(ExtensionType::ApplicationLayerProtocolNegotiation, alps.as_slice()),
            ExtendValue::ApplicationSettings(alps) => Extension::new_slice(ExtensionType::ApplicationSetting, alps.as_slice()),
            ExtendValue::ApplicationSettingOld(alps) => Extension::new_slice(ExtensionType::ApplicationSettingOld, alps.as_slice()),
            ExtendValue::EcPointFormats(formats) => Extension::new_slice(ExtensionType::EcPointFormats, formats.as_slice()),
            ExtendValue::CompressionCertificate(methods) => Extension::new_slice(ExtensionType::CompressionCertificate, methods.as_slice()),
            ExtendValue::RenegotiationInfo(info) => Extension::new_slice(ExtensionType::RenegotiationInfo, info.as_ref()),
            ExtendValue::SignedCertificateTimestamp => Extension::new_null(ExtensionType::SignedCertificateTimestamp),
            ExtendValue::SignatureAlgorithms(algorithms) => Extension::new_slice(ExtensionType::SignatureAlgorithms, algorithms.as_slice()),
            ExtendValue::PskKeyExchangeModes(modes) => Extension::new_slice(ExtensionType::PskKeyExchangeMode, modes.as_slice()),
            ExtendValue::SessionTicket(ticket) => Extension::new_slice(ExtensionType::SessionTicket, ticket.as_ref()),
            ExtendValue::EncryptedClientHello(encrypted_client_hello) => Extension::new_slice(ExtensionType::EncryptedClientHello, encrypted_client_hello.as_ref()),
            ExtendValue::ExtendedMasterSecret => Extension::new_null(ExtensionType::ExtendMasterSecret),
            ExtendValue::Reversed { typ, value } => Extension::new_slice(*typ, value.as_ref()),
        });
    }
    println!("{}", config.sni_len);
    let ret = unsafe {
        Record_build_custom(
            &mut writer,
            &mut connection,
            &config,
            *record_version,
            suites.len(),
            suites.as_ptr(),
            *message_version,
            extends.len(),
            extends.as_ptr(),
        )
    };
    println!("{} {} {:?}", writer.len(), ret, writer.filled());
    println!("{:#?}", RecordLayer::from_bytes(writer.filled(), reqtls::KeyExchangeAlg::NULL, false).unwrap());


    return;


    // println!("{:?}", hash::sm3_hex("sdsd").unwrap());
    // let mut f = File::open("TOKEN").unwrap();
    let record_bytes = hex::decode("16030107120100070e030348853c3196bf1baa176acac0b0fe608e384f64a48cb9d16eb17c52dfb9a73bd3201a5e217537bc3af3e314e4d89639ba76ce25114009dc2c2235660730c4e3899a0020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006a51a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b0000000e000c0000093338686d7a672e636e002b0007064a4a03040303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683200170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683208687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea000100").unwrap();
    println!("{:?}", RecordLayer::from_bytes(&record_bytes, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    let mut reader = Reader::from_slice(&record_bytes);
    let mut record = Record::default();
    let s = unsafe { Record_parse(&mut reader, &mut record) };
    println!("{:#?}", record);
    println!("{:?}", hex::decode("fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c").unwrap());
    // // unsafe { Record_free(s) };


    // let mut reader = Reader::from_slice(&record_bytes[5..]);
    // let mut message = MaybeUninit::uninit();
    // let ret = unsafe { Message_parse(&mut reader, RecordType::HandShake as u8, KeyExchangeAlg::ExchangeAlg_None, 0, message.as_mut_ptr()) };
    // println!("{}", ret);
    // let mut message = unsafe { message.assume_init() };
    // println!("{:#?}", unsafe { &message.parsed.handshake });
    // unsafe { Message_free(&mut message) };


    // let record = hex::decode("1603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9").unwrap();
    // println!("{:#?}", RecordLayer::from_bytes(&record, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    // let mut reader = Reader::from_slice(&record);
    // let s = unsafe { Record_parse(&mut reader, KeyExchangeAlg::ExchangeAlg_None, 0) };
    // println!("{:#?}", unsafe { s.as_ref() }.unwrap());
    //
    // let record = hex::decode("140303000101").unwrap();
    // println!("{:#?}", RecordLayer::from_bytes(&record, reqtls::KeyExchangeAlg::NULL, false).unwrap());
    // let mut reader = Reader::from_slice(&record);
    // let s = unsafe { Record_parse(&mut reader, KeyExchangeAlg::ExchangeAlg_None, 0) };
    // println!("{:#?}", unsafe { s.as_ref() }.unwrap());


    // let ptr = unsafe { s.as_ref().unwrap().message.handshake[0].parsed.client_hello.suites };
    // let len = unsafe { s.as_ref().unwrap().message.handshake[0].parsed.client_hello.suite_len } / 2;
    // let suites = unsafe { slice::from_raw_parts(ptr, len as usize) };
    // println!("{:04x?}", suites);

    // unsafe { Record_free(s); }
    return;
    // Buffer::check_subscription(fs::read_to_string("TOKEN").unwrap()).unwrap();

    let t = Time::now();
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "*/*",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "sec-fetch-user":"?1",
        "upgrade-insecure-requests":"1",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip,deflate,br,zstd",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "content-length": "0"
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    let fingerprint = Fingerprint::from_ja4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", fs::read_to_string("TOKEN").unwrap_or("".to_string())).unwrap();
    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(false)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        // .with_alpn(ALPN::Http20)
        .with_header_json(headers).unwrap()
        // .with_mtls(vec![], RsaKey::none(), Some(vec![cert]))
        .with_proxy(Proxy::try_from("http://180.117.50.133:3828").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 8080))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
        ;
    // let res = req.post("http://127.0.0.1:8000/log", json::object! {"on": false}).await.unwrap();
    // let res = req.get("https://fk1.moutai519.com.cn/bangcle/api/v1/1/1", None).await.unwrap().json().unwrap();
    // let res = req.post("http://127.0.0.1:8000/upload_wac", res).await.unwrap();
    // // println!("{}", res.raw_string());
    // let res = req.post("http://127.0.0.1:8000/generate", json::object! {
    //     "ua": "Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123",
    //     "body":{},
    //     "uid": "5656"
    // }).await.unwrap();
    // println!("{}", res.json().unwrap().pretty());
    // return;
    // req.connect("https://test.gmssl.cn/").await.unwrap();
    // let res = req.get("https://test.gmssl.cn/", None).await.unwrap();
    // println!("{}", res.raw_string());
    // let res = req.get("https://www.baidu.com", None).await.unwrap();
    // println!("{}", res.raw_string());


    // let url = "https://www.dickssportinggoods.com/p/2026-topps-flagship-football-mega-box-26topufang4p4ib5vqjhq/26topufang4p4ib5vqjhq";
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.dsR0yzVOEBuWxCU9cjAM4Q?w=32&h=32&qlt=96&pcl=fffffa&o=6&pid=1.2";
    // let sid1 = req.send(Method::GET, url, None).await.unwrap();
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.pnhuF5msYDWgeLYHsiLTig?w=32&h=32&qlt=95&pcl=fffffa&o=6&pid=1.2";
    // let sid2 = req.send(Method::POST, url, None).await.unwrap();

    // let res1 = req.recv(sid1).await.unwrap();
    // let res1 = req.get(url, None).await.unwrap();
    // println!("{}", res1.raw_string());
    // let res2 = req.recv(sid2).await.unwrap();
    // println!("{}", res2.raw_string());
    // println!("{}", Time::now().as_mills() - t.as_mills())

    // let res1 = req.get("https://docs.rs", None).await.unwrap();
    // let res1 = req.get("https://www.bing.com", None).await.unwrap();
    let res1 = req.get("https://202.89.233.101".sni("cn.bing.com"), None).await.unwrap();
    println!("{}", res1.raw_string());

    // req.set_auto_redirect(false);
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    // req.set_url("https://www.link114.cn/").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_proxy(Proxy::new_socks5("127.0.0.1", 10279));
    // req.set_url("https://m.baidu.com").await.unwrap();
    // req.set_url("https://www.sephora.com/").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap()
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    // let url: Url = "https://cn.bing.com".try_into().unwrap();
    // let url = "https://shop.lululemon.com/help/orders/gift-card-balance";


    // println!("{} {}", res1.header(), res2.header());
    // let res = req.get("https://m.sogou.com", None).await.unwrap();
    // let session=req.stream_mut().tls_session().cloned();
    // req.set_tls_session(session);
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.send("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get(url.params(params), None).await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/v1/carousel?&format=json&ecount=20&efirst=0&&").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());

}