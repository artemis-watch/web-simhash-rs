use std::collections::HashSet;

use crate::fingerprint::{SimHash64, DEFAULT_NEAR_DUP_DISTANCE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexConfig {
    pub max_distance: u32,
    pub tables: Vec<TableSpec>,
}

impl IndexConfig {
    pub fn google64_k3() -> Self {
        Self::from_block_widths(&[11, 11, 11, 11, 10, 10], 3, DEFAULT_NEAR_DUP_DISTANCE)
    }

    pub fn from_block_widths(
        block_widths: &[u8],
        matching_blocks: usize,
        max_distance: u32,
    ) -> Self {
        assert_eq!(
            block_widths
                .iter()
                .map(|width| u16::from(*width))
                .sum::<u16>(),
            64
        );
        assert!(matching_blocks > 0);
        assert!(matching_blocks <= block_widths.len());

        let blocks = block_positions(block_widths);
        let mut tables = Vec::new();
        let mut chosen = Vec::new();
        combinations(
            block_widths.len(),
            matching_blocks,
            0,
            &mut chosen,
            &mut |combo| {
                tables.push(TableSpec::from_selected_blocks(&blocks, combo));
            },
        );

        Self {
            max_distance,
            tables,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSpec {
    pub selected_blocks: Vec<usize>,
    pub permutation: [u8; 64],
    pub prefix_bits: u8,
}

impl TableSpec {
    fn from_selected_blocks(blocks: &[Vec<u8>], selected_blocks: &[usize]) -> Self {
        let selected: HashSet<_> = selected_blocks.iter().copied().collect();
        let mut order = Vec::with_capacity(64);

        for block in selected_blocks {
            order.extend(blocks[*block].iter().copied());
        }
        for (idx, block) in blocks.iter().enumerate() {
            if !selected.contains(&idx) {
                order.extend(block.iter().copied());
            }
        }

        let mut permutation = [0u8; 64];
        permutation.copy_from_slice(&order);
        let prefix_bits = selected_blocks
            .iter()
            .map(|block| blocks[*block].len() as u8)
            .sum();

        Self {
            selected_blocks: selected_blocks.to_vec(),
            permutation,
            prefix_bits,
        }
    }

    pub fn permute(&self, hash: SimHash64) -> u64 {
        let mut value = 0u64;
        for source_bit in self.permutation {
            value <<= 1;
            value |= (hash.0 >> source_bit) & 1;
        }
        value
    }

    pub fn prefix(&self, hash: SimHash64) -> u64 {
        leading_prefix(self.permute(hash), self.prefix_bits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub id: String,
    pub fingerprint: SimHash64,
    pub distance: u32,
}

#[derive(Debug, Clone)]
struct IndexedItem {
    id: String,
    fingerprint: SimHash64,
}

#[derive(Debug, Clone)]
struct TableEntry {
    permuted: u64,
    item_index: usize,
}

#[derive(Debug, Clone)]
struct Table {
    spec: TableSpec,
    entries: Vec<TableEntry>,
}

#[derive(Debug, Clone)]
pub struct SimHashIndex {
    config: IndexConfig,
    items: Vec<IndexedItem>,
    tables: Vec<Table>,
}

impl SimHashIndex {
    pub fn new(config: IndexConfig) -> Self {
        let tables = config
            .tables
            .iter()
            .cloned()
            .map(|spec| Table {
                spec,
                entries: Vec::new(),
            })
            .collect();

        Self {
            config,
            items: Vec::new(),
            tables,
        }
    }

    pub fn new_google64_k3() -> Self {
        Self::new(IndexConfig::google64_k3())
    }

    pub fn from_items<I, S>(config: IndexConfig, items: I) -> Self
    where
        I: IntoIterator<Item = (S, SimHash64)>,
        S: Into<String>,
    {
        let mut index = Self::new(config);
        for (id, fingerprint) in items {
            index.insert(id, fingerprint);
        }
        index
    }

    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn insert<S: Into<String>>(&mut self, id: S, fingerprint: SimHash64) {
        let item_index = self.items.len();
        self.items.push(IndexedItem {
            id: id.into(),
            fingerprint,
        });

        for table in &mut self.tables {
            table.entries.push(TableEntry {
                permuted: table.spec.permute(fingerprint),
                item_index,
            });
            table
                .entries
                .sort_by_key(|entry| (entry.permuted, entry.item_index));
        }
    }

    pub fn query(&self, fingerprint: SimHash64) -> Vec<Match> {
        let mut candidates = HashSet::new();

        for table in &self.tables {
            let permuted = table.spec.permute(fingerprint);
            let (start, end) = prefix_range(permuted, table.spec.prefix_bits);
            let start_idx = lower_bound(&table.entries, start);
            let end_idx = upper_bound(&table.entries, end);

            for entry in &table.entries[start_idx..end_idx] {
                candidates.insert(entry.item_index);
            }
        }

        let mut matches = Vec::new();
        for item_index in candidates {
            let item = &self.items[item_index];
            let distance = fingerprint.hamming_distance(item.fingerprint);
            if distance <= self.config.max_distance {
                matches.push(Match {
                    id: item.id.clone(),
                    fingerprint: item.fingerprint,
                    distance,
                });
            }
        }

        matches.sort_by(|a, b| a.distance.cmp(&b.distance).then_with(|| a.id.cmp(&b.id)));
        matches
    }
}

fn block_positions(widths: &[u8]) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut next_msb = 63i16;

    for width in widths {
        let mut block = Vec::new();
        for _ in 0..*width {
            block.push(next_msb as u8);
            next_msb -= 1;
        }
        blocks.push(block);
    }

    blocks
}

fn combinations<F>(n: usize, k: usize, start: usize, chosen: &mut Vec<usize>, on_combo: &mut F)
where
    F: FnMut(&[usize]),
{
    if chosen.len() == k {
        on_combo(chosen);
        return;
    }

    for idx in start..n {
        chosen.push(idx);
        combinations(n, k, idx + 1, chosen, on_combo);
        chosen.pop();
    }
}

fn leading_prefix(value: u64, prefix_bits: u8) -> u64 {
    if prefix_bits == 0 {
        0
    } else {
        value >> (64 - prefix_bits)
    }
}

fn prefix_range(permuted: u64, prefix_bits: u8) -> (u64, u64) {
    if prefix_bits == 0 {
        return (0, u64::MAX);
    }
    if prefix_bits == 64 {
        return (permuted, permuted);
    }

    let prefix = leading_prefix(permuted, prefix_bits);
    let suffix_bits = 64 - prefix_bits;
    let start = prefix << suffix_bits;
    let end = start | ((1u64 << suffix_bits) - 1);
    (start, end)
}

fn lower_bound(entries: &[TableEntry], value: u64) -> usize {
    let mut left = 0usize;
    let mut right = entries.len();
    while left < right {
        let mid = left + (right - left) / 2;
        if entries[mid].permuted < value {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

fn upper_bound(entries: &[TableEntry], value: u64) -> usize {
    let mut left = 0usize;
    let mut right = entries.len();
    while left < right {
        let mid = left + (right - left) / 2;
        if entries[mid].permuted <= value {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_config_has_twenty_tables() {
        let config = IndexConfig::google64_k3();
        assert_eq!(config.max_distance, 3);
        assert_eq!(config.tables.len(), 20);
        assert!(config
            .tables
            .iter()
            .all(|table| matches!(table.prefix_bits, 31 | 32 | 33)));
    }

    #[test]
    fn permutation_moves_selected_block_to_prefix() {
        let config = IndexConfig::from_block_widths(&[32, 32], 1, 1);
        let first = &config.tables[0];
        let second = &config.tables[1];
        let hash = SimHash64(0xaaaa_aaaa_5555_5555);

        assert_eq!(first.prefix(hash), 0xaaaa_aaaa);
        assert_eq!(second.prefix(hash), 0x5555_5555);
    }

    #[test]
    fn query_finds_items_within_threshold() {
        let base = SimHash64(0x1234_5678_90ab_cdef);
        let within = SimHash64(base.0 ^ 0b111);
        let outside = SimHash64(base.0 ^ 0b1_1111);
        let index = SimHashIndex::from_items(
            IndexConfig::google64_k3(),
            [("within", within), ("outside", outside)],
        );

        let matches = index.query(base);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "within");
        assert_eq!(matches[0].distance, 3);
    }

    #[test]
    fn query_results_are_sorted_by_distance() {
        let base = SimHash64(0xffff_0000_ffff_0000);
        let one = SimHash64(base.0 ^ 0b1);
        let three = SimHash64(base.0 ^ 0b111);
        let index =
            SimHashIndex::from_items(IndexConfig::google64_k3(), [("three", three), ("one", one)]);

        let matches = index.query(base);
        assert_eq!(matches[0].id, "one");
        assert_eq!(matches[1].id, "three");
    }

    #[test]
    fn empty_index_returns_no_matches() {
        let index = SimHashIndex::new_google64_k3();
        assert!(index.is_empty());
        assert!(index.query(SimHash64(42)).is_empty());
    }
}
