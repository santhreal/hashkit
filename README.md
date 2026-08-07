# hashkit

Hashing primitives shared across the Santh performance crates: fast
non-cryptographic hashes (FNV-1a, SplitMix64, wyhash) for in-memory indexing
and bloom filters, plus standard BLAKE3 and SHA-256 for content addressing.

The non-cryptographic hashes are not suitable for security-sensitive use.
When you compare cryptographic digests, use `hashkit::secure_compare` instead
of `==` to avoid timing side-channels.

## Quick Start

```rust
use hashkit::{bloom_hash_pair, bloom_probes};

// Derive k bloom-filter probe indices from one double-hashed pair.
let (h1, h2) = bloom_hash_pair(b's', b'a');
let probes: Vec<usize> = bloom_probes(h1, h2, 4, 1024).collect();

assert_eq!(probes.len(), 4);
assert!(probes.iter().all(|&i| i < 1024));
```

For content-addressed storage, hash with BLAKE3 and compare digests in
constant time:

```rust
let digest = hashkit::blake3_hash::hash(b"hello");

assert!(hashkit::secure_compare(&digest, &hashkit::blake3_hash::hash(b"hello")));
```

For streaming Shannon entropy calculation over data chunks:

```rust
use hashkit::entropy::EntropyCounter;

let mut counter = EntropyCounter::new();
counter.update(b"The quick ");
counter.update(b"brown fox");
let entropy = counter.entropy();
assert!(entropy > 0.0);
```
## License

MIT OR Apache-2.0
