use std::{env, fs};
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    println!("cargo:rustc-link-search={}/lib/{}/{}", manifest_dir, target_os, target_env);
    println!("cargo:rustc-link-lib=dylib=bcrypto");
    println!("cargo:rustc-link-lib=dylib=zstd");
    let mut dll_src = PathBuf::from_str(manifest_dir.as_str()).unwrap();
    dll_src.push("lib");
    dll_src.push(target_os.as_str());
    dll_src.push(target_env.as_str());
    let out_dir = env::var("OUT_DIR").unwrap();
    let path = Path::new(out_dir.as_str()).parent().unwrap().parent().unwrap().parent().unwrap();
    let mut dll_dst = path.to_path_buf();
    match (target_os.as_str(), target_env.as_str()) {
        ("windows", "msvc") => {
            println!("cargo:rustc-link-lib=advapi32");
            dll_src.push("bcrypto.dll");
            dll_dst.push("bcrypto.dll")
        }
        ("windows", "gnu") => {
            println!("cargo:rustc-link-lib=dylib=advapi32");
            println!("cargo:rustc-link-lib=stdc++");
            dll_src.push("libbcrypto.dll");
            dll_dst.push("libbcrypto.dll")
        }
        ("linux", "gnu") => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
            dll_src.push("libbcrypto.so");
            dll_dst.push("libbcrypto.so")
        }
        (_, _) => {}
    }
    fs::copy(dll_src, dll_dst).unwrap();
}
