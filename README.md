# web-simhash-rs

a small, dependency-free Rust library for web-page near-duplicate detection. It follows the public Google WWW 2007 SimHash paper as closely as practical:
weighted document features, 64-bit fingerprints, Hamming distance comparison,
and a multi-table index for finding fingerprints within a small bit distance.

## Install

```bash
cargo add web-simhash
```

## Example

```rust
use web_simhash::{SimHash64, SimHashIndex, WebFeatureExtractor};

let extractor = WebFeatureExtractor::default();
let a = SimHash64::from_html("<main>Example page</main>", &extractor);
let b = SimHash64::from_html("<main>Example page updated</main>", &extractor);

let mut index = SimHashIndex::new_google64_k3();
index.insert("a", a);

let matches = index.query(b);
```
