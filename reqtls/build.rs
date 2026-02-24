use std::env;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let typ = if cfg!(feature = "dylib") { "dylib" } else { "static" };
    if typ == "static" { println!("cargo:rustc-link-search={}/lib/{}/{}", manifest_dir, target_os, target_env); }
    println!("cargo:rustc-link-lib={}=crypto", typ);
    println!("cargo:rustc-link-lib={}=zstd", typ);
    // println!("cargo:rustc-link-lib=versus");
    match (target_os.as_str(), target_env.as_str()) {
        ("windows", "msvc") => println!("cargo:rustc-link-lib=advapi32"),
        ("windows", "gnu") => {
            println!("cargo:rustc-link-lib=dylib=advapi32");
            println!("cargo:rustc-link-lib=stdc++");
        }
        ("linux", "gnu") => println!("cargo:rustc-link-lib=dylib=stdc++"),
        (_, _) => {}
    }
}
