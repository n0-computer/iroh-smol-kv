use std::sync::LazyLock;

/// We export the entire API at top level since this is what go-uniffi-bindgen will do anyway.
mod streams;
pub use streams::*;
mod db;
pub use db::*;
#[cfg(test)]
mod tests;

/// Lazily initialized Tokio runtime for use in uniffi methods that need a runtime.
static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

uniffi::setup_scaffolding!();
