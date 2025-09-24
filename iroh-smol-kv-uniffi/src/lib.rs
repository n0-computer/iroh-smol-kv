uniffi::setup_scaffolding!();

mod code;
pub use code::*;

include!(concat!(env!("OUT_DIR"), "/generated_macro.rs"));
