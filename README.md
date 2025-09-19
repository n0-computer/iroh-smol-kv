# iroh-smol-kv

A tiny in memory replicated key value store that syncs via an [iroh-gossip] topic.

The store provides a two level map, where the first level is a *scope* (a [PublicKey])
and the second level is an arbitrary [Bytes] key. Values are [Bytes], but come
with a timestamp.

Values contain a signature over `(key, value, timestamp)` so they
can be replicated.

The store can be observed, with filters on scope, key and timestamp.

[iroh-gossip]: https://docs.rs/iroh-gossip/latest/iroh_gossip/
[Bytes]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
[PublicKey]: https://docs.rs/iroh/latest/iroh/struct.PublicKey.html
