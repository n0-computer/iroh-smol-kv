use iroh_smol_kv as w;

/// A signed value stored in the database.
#[derive(Debug, Clone, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct SignedValue(w::SignedValue);

impl From<w::SignedValue> for SignedValue {
    fn from(v: w::SignedValue) -> Self {
        Self(v)
    }
}

impl From<SignedValue> for w::SignedValue {
    fn from(v: SignedValue) -> Self {
        v.0
    }
}
