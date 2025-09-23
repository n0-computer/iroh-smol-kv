#[uniffi::export]
fn hello(name: &str) -> String {
    format!("Hello, {}!", name)
}

uniffi::setup_scaffolding!();
