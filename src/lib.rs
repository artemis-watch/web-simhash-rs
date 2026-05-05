//! Web-oriented SimHash.
//!
//! This crate implements the public pieces of the Google WWW 2007 near-duplicate
//! detection paper: weighted-feature SimHash, 64-bit Hamming comparison, and a
//! multi-table online lookup index. It does not attempt to reproduce Google's
//! private crawler feature pipeline.

mod fingerprint;
mod index;
mod web;

pub use fingerprint::{
    fnv1a64, FeatureHash, SimHash64, SimHashOptions, TieBreaker, WeightedFeature,
    DEFAULT_NEAR_DUP_DISTANCE,
};
pub use index::{IndexConfig, Match, SimHashIndex, TableSpec};
pub use web::{WebFeatureExtractor, WebFeatureOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_html_near_duplicate_lookup() {
        let extractor = WebFeatureExtractor::default();
        let canonical = SimHash64::from_html(
            r#"
            <html>
              <head><title>Ignored title chrome</title></head>
              <body>
                <nav>Home About Contact</nav>
                <main>
                  <h1>Rust SimHash for web crawling</h1>
                  <p>Near duplicate web documents differ mostly in counters and ads.</p>
                  <p>The crawler should avoid fetching the same useful content twice.</p>
                </main>
                <aside>Advertisement 12345</aside>
              </body>
            </html>
            "#,
            &extractor,
        );
        let duplicate = SimHash64::from_html(
            r#"
            <html>
              <body>
                <main>
                  <h1>Rust SimHash for web crawling</h1>
                  <p>Near duplicate web documents differ mostly in counters and ads.</p>
                  <p>The crawler should avoid fetching the same useful content twice.</p>
                </main>
                <aside>Advertisement 99999</aside>
              </body>
            </html>
            "#,
            &extractor,
        );

        let mut index = SimHashIndex::new_google64_k3();
        index.insert("canonical", canonical);
        let matches = index.query(duplicate);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "canonical");
        assert!(matches[0].distance <= DEFAULT_NEAR_DUP_DISTANCE);
    }
}
