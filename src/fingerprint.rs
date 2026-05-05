use crate::web::WebFeatureExtractor;

/// The Google paper's empirically reasonable threshold for 64-bit web-page
/// fingerprints.
pub const DEFAULT_NEAR_DUP_DISTANCE: u32 = 3;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;
const BYTE_LANE_MASK: u64 = 0x0101_0101_0101_0101;

/// Deterministic 64-bit FNV-1a hash.
///
/// The hash is used for reproducible feature hashing. It is not cryptographic.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Tie behavior when a SimHash accumulator lands exactly on zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreaker {
    Zero,
    One,
    Alternating,
}

/// Fingerprint construction options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimHashOptions {
    pub tie_breaker: TieBreaker,
}

impl Default for SimHashOptions {
    fn default() -> Self {
        Self {
            tie_breaker: TieBreaker::Alternating,
        }
    }
}

/// A string feature with an integer weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedFeature {
    pub key: String,
    pub weight: u32,
}

impl WeightedFeature {
    pub fn new(key: impl Into<String>, weight: u32) -> Self {
        Self {
            key: key.into(),
            weight,
        }
    }

    pub fn hash(&self) -> FeatureHash {
        let mut bytes = Vec::with_capacity("feature:".len() + self.key.len());
        bytes.extend_from_slice(b"feature:");
        bytes.extend_from_slice(self.key.as_bytes());
        FeatureHash {
            hash: fnv1a64(&bytes),
            weight: self.weight,
        }
    }
}

/// A pre-hashed feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureHash {
    pub hash: u64,
    pub weight: u32,
}

impl FeatureHash {
    pub fn new(hash: u64, weight: u32) -> Self {
        Self { hash, weight }
    }
}

/// A 64-bit SimHash fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SimHash64(pub u64);

impl SimHash64 {
    pub fn from_features(features: &[WeightedFeature]) -> Self {
        Self::from_features_with_options(features, SimHashOptions::default())
    }

    pub fn from_features_with_options(
        features: &[WeightedFeature],
        options: SimHashOptions,
    ) -> Self {
        let hashes = features.iter().map(WeightedFeature::hash);
        Self::from_feature_hashes_with_options(hashes, options)
    }

    pub fn from_feature_hashes<I>(hashes: I) -> Self
    where
        I: IntoIterator<Item = FeatureHash>,
    {
        Self::from_feature_hashes_with_options(hashes, SimHashOptions::default())
    }

    pub fn from_feature_hashes_with_options<I>(hashes: I, options: SimHashOptions) -> Self
    where
        I: IntoIterator<Item = FeatureHash>,
    {
        let mut accum = [0i64; 64];
        for feature in hashes {
            if feature.weight == 0 {
                continue;
            }
            let weight = i64::from(feature.weight);
            for bit in 0..64 {
                if ((feature.hash >> bit) & 1) == 1 {
                    accum[bit] += weight;
                } else {
                    accum[bit] -= weight;
                }
            }
        }
        Self(bits_from_signed_accumulator(&accum, options))
    }

    /// Fast unweighted SimHash over pre-hashed elements.
    ///
    /// This uses the byte-lane counter trick described by Otmar Ertl's
    /// FastSimHash article: each byte lane in a `u64` counts one bit position,
    /// then lanes are flushed before they can overflow. The result is equivalent
    /// to the normal unweighted SimHash path.
    pub fn from_hashes_unweighted_fast(hashes: &[u64]) -> Self {
        Self::from_hashes_unweighted_fast_with_options(hashes, SimHashOptions::default())
    }

    pub fn from_hashes_unweighted_fast_with_options(
        hashes: &[u64],
        options: SimHashOptions,
    ) -> Self {
        let mut ones = [0u32; 64];
        let mut lanes = [0u64; 8];
        let mut in_lanes = 0u16;

        for hash in hashes {
            for shift in 0..8 {
                lanes[shift] = lanes[shift].wrapping_add((hash >> shift) & BYTE_LANE_MASK);
            }
            in_lanes += 1;
            if in_lanes == 255 {
                flush_lanes(&mut ones, &mut lanes);
                in_lanes = 0;
            }
        }

        if in_lanes > 0 {
            flush_lanes(&mut ones, &mut lanes);
        }

        let total = hashes.len() as i64;
        let mut accum = [0i64; 64];
        for bit in 0..64 {
            accum[bit] = i64::from(ones[bit]) * 2 - total;
        }
        Self(bits_from_signed_accumulator(&accum, options))
    }

    pub fn from_text(text: &str, extractor: &WebFeatureExtractor) -> Self {
        let features = extractor.extract_from_text(text);
        Self::from_features(&features)
    }

    pub fn from_html(html: &str, extractor: &WebFeatureExtractor) -> Self {
        let features = extractor.extract_from_html(html);
        Self::from_features(&features)
    }

    pub fn hamming_distance(self, other: Self) -> u32 {
        (self.0 ^ other.0).count_ones()
    }

    pub fn similarity(self, other: Self) -> f64 {
        1.0 - f64::from(self.hamming_distance(other)) / 64.0
    }

    pub fn is_near_duplicate(self, other: Self, max_distance: u32) -> bool {
        self.hamming_distance(other) <= max_distance
    }
}

fn flush_lanes(ones: &mut [u32; 64], lanes: &mut [u64; 8]) {
    for shift in 0..8 {
        let lane = lanes[shift];
        for byte in 0..8 {
            let bit = shift + byte * 8;
            ones[bit] += ((lane >> (byte * 8)) & 0xff) as u32;
        }
        lanes[shift] = 0;
    }
}

fn bits_from_signed_accumulator(accum: &[i64; 64], options: SimHashOptions) -> u64 {
    let mut value = 0u64;
    for (bit, count) in accum.iter().enumerate() {
        let set = match count.cmp(&0) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => match options.tie_breaker {
                TieBreaker::Zero => false,
                TieBreaker::One => true,
                TieBreaker::Alternating => bit % 2 == 1,
            },
        };
        if set {
            value |= 1u64 << bit;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_is_deterministic() {
        assert_eq!(fnv1a64(b"test string"), 10983430520173899754);
        assert_eq!(fnv1a64(b"test string"), fnv1a64(b"test string"));
        assert_ne!(fnv1a64(b"test string"), fnv1a64(b"test thing"));
    }

    #[test]
    fn weighted_features_change_the_result() {
        let light = vec![
            WeightedFeature::new("term:my", 1),
            WeightedFeature::new("term:car", 1),
            WeightedFeature::new("term:black", 1),
        ];
        let heavy = vec![
            WeightedFeature::new("term:my", 1),
            WeightedFeature::new("term:car", 1),
            WeightedFeature::new("term:black", 8),
        ];

        assert_ne!(
            SimHash64::from_features(&light),
            SimHash64::from_features(&heavy)
        );
    }

    #[test]
    fn explicit_feature_weights_match_repetition() {
        let repeated_hash = fnv1a64(b"feature:repeated");
        let weighted = SimHash64::from_feature_hashes([FeatureHash::new(repeated_hash, 3)]);
        let repeated = SimHash64::from_feature_hashes([
            FeatureHash::new(repeated_hash, 1),
            FeatureHash::new(repeated_hash, 1),
            FeatureHash::new(repeated_hash, 1),
        ]);

        assert_eq!(weighted, repeated);
    }

    #[test]
    fn hamming_distance_and_similarity_work() {
        let a = SimHash64(0);
        let b = SimHash64(u64::MAX);
        let c = SimHash64(0b1011);

        assert_eq!(a.hamming_distance(a), 0);
        assert_eq!(a.hamming_distance(b), 64);
        assert_eq!(a.hamming_distance(c), 3);
        assert_eq!(a.similarity(a), 1.0);
        assert_eq!(a.similarity(b), 0.0);
    }

    #[test]
    fn fast_unweighted_path_matches_standard_path() {
        let hashes: Vec<u64> = (0..600)
            .map(|n| fnv1a64(format!("feature-{n}").as_bytes()))
            .collect();
        let fast = SimHash64::from_hashes_unweighted_fast(&hashes);
        let standard =
            SimHash64::from_feature_hashes(hashes.iter().copied().map(|h| FeatureHash::new(h, 1)));

        assert_eq!(fast, standard);
    }

    #[test]
    fn tie_breakers_are_deterministic() {
        let empty_zero = SimHash64::from_feature_hashes_with_options(
            [],
            SimHashOptions {
                tie_breaker: TieBreaker::Zero,
            },
        );
        let empty_one = SimHash64::from_feature_hashes_with_options(
            [],
            SimHashOptions {
                tie_breaker: TieBreaker::One,
            },
        );
        let empty_alt = SimHash64::from_feature_hashes_with_options(
            [],
            SimHashOptions {
                tie_breaker: TieBreaker::Alternating,
            },
        );

        assert_eq!(empty_zero.0, 0);
        assert_eq!(empty_one.0, u64::MAX);
        assert_eq!(empty_alt.0, 0xaaaa_aaaa_aaaa_aaaa);
    }
}
