use std::env;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={}/lib", manifest_dir);
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=advapi32");
}