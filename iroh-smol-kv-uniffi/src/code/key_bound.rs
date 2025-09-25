use std::ops::Bound;

use bytes::Bytes;

/// A bound on keys for filtering.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum KeyBound {
    Unbounded,
    Included(Vec<u8>),
    Excluded(Vec<u8>),
}

impl From<Bound<Bytes>> for KeyBound {
    fn from(b: Bound<Bytes>) -> Self {
        match b {
            Bound::Unbounded => KeyBound::Unbounded,
            Bound::Included(b) => KeyBound::Included(b.into()),
            Bound::Excluded(b) => KeyBound::Excluded(b.into()),
        }
    }
}

impl From<KeyBound> for Bound<Bytes> {
    fn from(b: KeyBound) -> Self {
        match b {
            KeyBound::Unbounded => Bound::Unbounded,
            KeyBound::Included(b) => Bound::Included(b.into()),
            KeyBound::Excluded(b) => Bound::Excluded(b.into()),
        }
    }
}
