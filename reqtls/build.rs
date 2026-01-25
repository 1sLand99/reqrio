fn main() {
    println!("cargo:rustc-link-search=reqtls/lib");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=advapi32");
}