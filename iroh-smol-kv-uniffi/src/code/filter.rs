use std::{collections::HashSet, sync::Arc};

use iroh_smol_kv as w;
use snafu::Snafu;

use super::{KeyBound, PublicKey, TimeBound};

#[derive(uniffi::Object, Debug, Clone)]
pub struct Filter {
    min_key: KeyBound,
    max_key: KeyBound,
    min_time: TimeBound,
    max_time: TimeBound,
    scope: Vec<Arc<PublicKey>>,
}

impl From<w::Filter> for Filter {
    fn from(f: w::Filter) -> Self {
        let min_key = f.key.0.into();
        let max_key = f.key.1.into();
        let min_time = f.timestamp.0.into();
        let max_time = f.timestamp.1.into();
        let scope = f
            .scope
            .map(|s| {
                s.into_iter()
                    .map(|k| Arc::new(PublicKey::from(k)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            min_key,
            max_key,
            min_time,
            max_time,
            scope,
        }
    }
}

impl From<Filter> for w::Filter {
    fn from(f: Filter) -> Self {
        let min_key = f.min_key.into();
        let max_key = f.max_key.into();
        let min_time = f.min_time.into();
        let max_time = f.max_time.into();
        let scope = if f.scope.is_empty() {
            None
        } else {
            let mut set = HashSet::with_capacity(f.scope.len());
            for k in f.scope {
                set.insert(iroh::PublicKey::from(k.as_ref()));
            }
            Some(set)
        };
        w::Filter {
            key: (min_key, max_key),
            timestamp: (min_time, max_time),
            scope,
        }
    }
}

#[uniffi::export]
impl Filter {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            min_key: KeyBound::Unbounded,
            max_key: KeyBound::Unbounded,
            min_time: TimeBound::Unbounded,
            max_time: TimeBound::Unbounded,
            scope: Vec::new(),
        })
    }

    #[uniffi::constructor]
    pub fn parse(text: String) -> Result<Arc<Self>, FilterParseError> {
        use std::str::FromStr;

        iroh_smol_kv::Filter::from_str(&text)
            .map_err(|e| FilterParseError::Invalid {
                message: e.to_string(),
            })
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn scopes(mut self: Arc<Self>, scopes: Vec<Arc<PublicKey>>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.scope = scopes;
        self
    }

    pub fn scope(self: Arc<Self>, scope: Arc<PublicKey>) -> Arc<Self> {
        self.scopes(vec![scope])
    }

    pub fn keys(mut self: Arc<Self>, min: KeyBound, max: KeyBound) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.min_key = min;
        this.max_key = max;
        self
    }

    pub fn key_range(self: Arc<Self>, min: Vec<u8>, max: Vec<u8>) -> Arc<Self> {
        self.keys(KeyBound::Included(min), KeyBound::Excluded(max))
    }

    pub fn key_prefix(mut self: Arc<Self>, prefix: Vec<u8>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        let mut end = prefix.clone();
        if iroh_smol_kv::util::next_prefix(&mut end) {
            this.min_key = KeyBound::Included(prefix);
            this.max_key = KeyBound::Excluded(end);
        } else {
            this.min_key = KeyBound::Included(prefix);
            this.max_key = KeyBound::Unbounded;
        }
        self
    }

    pub fn timestamps(mut self: Arc<Self>, min: TimeBound, max: TimeBound) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.min_time = min;
        this.max_time = max;
        self
    }

    pub fn time_range(self: Arc<Self>, min: u64, max: u64) -> Arc<Self> {
        self.timestamps(TimeBound::Included(min), TimeBound::Excluded(max))
    }
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum FilterParseError {
    Invalid { message: String },
}
