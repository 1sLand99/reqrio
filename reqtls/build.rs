use std::env;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    match (target_os.as_ref(), target_env.as_ref()) {
        ("windows", "msvc") => {
            println!("cargo:rustc-link-search={}/lib", manifest_dir);
            println!("cargo:rustc-link-lib=crypto_win_msvc");
            println!("cargo:rustc-link-lib=advapi32");
        }
        ("linux", "gnu") => {
            println!("cargo:rustc-link-search={}/lib", manifest_dir);
            println!("cargo:rustc-link-lib=crypto_linux_gnu");
        }
        _ => {}
    }
}
