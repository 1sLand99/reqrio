use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        tls:{
            any(feature = "aync", feature = "sync")
        }
        ,fpr:{any(feature = "fpr")}
    }
}
