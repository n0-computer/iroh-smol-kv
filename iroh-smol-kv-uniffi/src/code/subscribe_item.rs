use std::sync::Arc;

use iroh_smol_kv as w;

use super::{PublicKey, SignedValue};

#[derive(Clone, uniffi::Enum)]
pub enum SubscribeItem {
    Entry {
        scope: Arc<PublicKey>,
        key: Vec<u8>,
        value: Arc<SignedValue>,
    },
    CurrentDone,
    Expired {
        scope: Arc<PublicKey>,
        key: Vec<u8>,
        timestamp: u64,
    },
}

impl std::fmt::Debug for SubscribeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        w::SubscribeItem::from(self.clone()).fmt(f)
    }
}

impl From<SubscribeItem> for w::SubscribeItem {
    fn from(item: SubscribeItem) -> Self {
        match item {
            SubscribeItem::Entry { scope, key, value } => w::SubscribeItem::Entry((
                iroh::PublicKey::from(scope.as_ref()),
                key.into(),
                w::SignedValue::from(value.as_ref().clone()),
            )),
            SubscribeItem::CurrentDone => w::SubscribeItem::CurrentDone,
            SubscribeItem::Expired {
                scope,
                key,
                timestamp,
            } => w::SubscribeItem::Expired((
                iroh::PublicKey::from(scope.as_ref()),
                key.into(),
                timestamp,
            )),
        }
    }
}

impl From<w::SubscribeItem> for SubscribeItem {
    fn from(item: w::SubscribeItem) -> Self {
        match item {
            w::SubscribeItem::Entry((scope, key, value)) => SubscribeItem::Entry {
                scope: Arc::new(PublicKey::from(scope)),
                key: key.to_vec(),
                value: Arc::new(SignedValue::from(value)),
            },
            w::SubscribeItem::CurrentDone => SubscribeItem::CurrentDone,
            w::SubscribeItem::Expired((scope, key, timestamp)) => SubscribeItem::Expired {
                scope: Arc::new(PublicKey::from(scope)),
                key: key.to_vec(),
                timestamp,
            },
        }
    }
}

#[uniffi::export]
pub fn subscribe_item_debug(item: &SubscribeItem) -> String {
    // By reference
    format!("{item:?}")
}
