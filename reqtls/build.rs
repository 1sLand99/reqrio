use std::path::PathBuf;
use std::{env, fs};

struct LibName {
    bcrypto_name: &'static str,
    zap_name: &'static str,
}

struct Target {
    name: &'static str,
    env: &'static str,
    arch: &'static str,
    dylib_name: LibName,
    static_name: LibName,
}

impl Target {
    pub fn lib_path(&self) -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut path = PathBuf::from(manifest_dir);
        path = path.join("lib").join(self.name).join(self.arch);
        if self.name != "apple" {
            path = path.join(self.env);
        }
        path
    }

    pub fn bcrypto_name(&self) -> &str {
        match cfg!(feature = "static_link") {
            true => self.static_name.bcrypto_name,
            false => self.dylib_name.bcrypto_name,
        }
    }

    pub fn zap_name(&self) -> &str {
        match cfg!(feature = "static_link") {
            true => self.static_name.zap_name,
            false => self.dylib_name.zap_name,
        }
    }
}


const TARGETS: [Target; 4] = [
    Target {
        name: "windows",
        env: "msvc",
        arch: "x86_64",
        dylib_name: LibName {
            bcrypto_name: "bcrypto.dll",
            zap_name: "zap.dll",
        },
        static_name: LibName {
            bcrypto_name: "bcrypto.lib",
            zap_name: "zap.lib",
        },
    },
    Target {
        name: "windows",
        env: "gnu",
        arch: "x86_64",
        dylib_name: LibName {
            bcrypto_name: "libbcrypto.dll",
            zap_name: "libzap.dll",
        },
        static_name: LibName {
            bcrypto_name: "libbcrypto.a",
            zap_name: "libzap.a",
        },
    },
    Target {
        name: "linux",
        env: "gnu",
        arch: "x86_64",
        dylib_name: LibName {
            bcrypto_name: "libbcrypto.so",
            zap_name: "libzap.so",
        },
        static_name: LibName {
            bcrypto_name: "libbcrypto.a",
            zap_name: "libzap.a",
        },
    },
    Target {
        name: "apple",
        env: "",
        arch: "aarch64",
        dylib_name: LibName {
            bcrypto_name: "libbcrypto.dylib",
            zap_name: "libzap.dylib",
        },
        static_name: LibName {
            bcrypto_name: "libbcrypto.a",
            zap_name: "libzap.a",
        },
    }
];


fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = target_dir.ancestors().nth(3).unwrap();
    let target = TARGETS.iter().find(|x| {
        x.name == target_os && x.env == target_env && x.arch == arch
    }).expect("Target not supported");
    if cfg!(feature = "static_link") {
        todo!()
    } else {
        let lib_path = target.lib_path();
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=dylib=bcrypto");
        println!("cargo:rustc-link-lib=dylib=zap");
        fs::copy(lib_path.join(target.bcrypto_name()), target_dir.join(target.bcrypto_name())).unwrap();
        fs::copy(lib_path.join(target.zap_name()), target_dir.join(target.zap_name())).unwrap();
        fs::copy(lib_path.join(target.bcrypto_name()), target_dir.join("deps").join(target.bcrypto_name())).unwrap();
        fs::copy(lib_path.join(target.zap_name()), target_dir.join("deps").join(target.zap_name())).unwrap();
    }
}
