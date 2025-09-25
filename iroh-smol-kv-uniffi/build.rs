//! Takes the content of src/code.rs and wraps it in a macro called
//! `generate_uniffi_support!`, writing the result to a file in OUT_DIR.
//!
//! For uniffi implementations that don't work well with multiple crates,
//! you can implement the entire uniffi interface in your uniffi crate
//! using the macro.
use std::{env, fs, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_macro.rs");

    let mut all = String::new();
    for entry in fs::read_dir("src/code").expect("Failed to read src/code directory") {
        let entry = entry.expect("Failed to read entry in src/code");
        assert!(
            entry
                .file_type()
                .expect("Failed to get file type")
                .is_file()
        );
        let path = entry.path();
        assert!(path.extension().and_then(|s| s.to_str()) == Some("rs"));
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("Failed to get file stem");
        let contents = fs::read_to_string(&path).expect("Failed to read code file");
        all.push_str(&format!(
            r#"mod {stem} {{
{contents}
}}
pub use {stem}::*;
"#
        ));
    }

    // Wrap it in a macro
    let macro_content = format!(
        r#"
/// Generates the entire uniffi wrapper code in your crate.
///
/// This is needed if you have an uniffi code generator such as uniffi-bindgen-go that does not work well with
/// multiple crates exposing uniffi interfaces.
#[macro_export]
macro_rules! generate_uniffi_support {{
    () => {{
{all}
    }};
}}
"#
    );

    // Write the generated macro to OUT_DIR
    fs::write(&dest_path, macro_content).expect("Failed to write generated macro");

    // Tell Cargo to rerun if code.rs changes
    println!("cargo:rerun-if-changed=src/code/*");
}
