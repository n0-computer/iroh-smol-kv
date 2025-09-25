mod code;
pub use code::*;

uniffi::setup_scaffolding!();

include!(concat!(env!("OUT_DIR"), "/generated_macro.rs"));
