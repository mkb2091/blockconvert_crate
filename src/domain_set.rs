use fxhash::FxHashMap;
use fxhash::FxHashSet;

use crate::domain::DOMAIN_MAX_LENGTH;
use crate::Domain;

use std::sync::Arc;

use std::hash::{Hash, Hasher};

use parking_lot::Mutex;

const DEFAULT_SHARDS: usize = 1024;
type DefaultHasher = std::collections::hash_map::RandomState;

pub type DomainSetShardedDefault = DomainSetSharded<DefaultHasher>;

#[derive(Clone)]
pub struct DomainSetSharded<H: std::hash::BuildHasher> {
    shards: Vec<Arc<Mutex<DomainSet>>>,
    hasher: H,
}

impl Default for DomainSetSharded<DefaultHasher> {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSetSharded<DefaultHasher> {
    pub fn new() -> Self {
        Self::with_shards_and_hasher(DEFAULT_SHARDS, DefaultHasher::new())
    }
    pub fn with_shards(shard_count: usize) -> Self {
        Self::with_shards_and_hasher(shard_count, DefaultHasher::new())
    }
}

impl<T: std::hash::BuildHasher> DomainSetSharded<T> {
    pub fn with_shards_and_hasher(shard_count: usize, hasher: T) -> Self {
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Arc::new(Mutex::new(DomainSet::new())));
        }
        Self { shards, hasher }
    }
    fn get_location(&self, data: &[u8]) -> usize {
        let mut hasher = self.hasher.build_hasher();
        data.hash(&mut hasher);
        let hash = hasher.finish();
        hash as usize % self.shards.len()
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        assert!(data.len() < DOMAIN_MAX_LENGTH);
        self.shards[self.get_location(data)].lock().contains(data)
    }
    pub fn contains_str(&self, data: &str) -> bool {
        self.contains(data.as_bytes())
    }

    pub fn insert(&self, data: &[u8]) -> bool {
        assert!(data.len() < DOMAIN_MAX_LENGTH);
        self.shards[self.get_location(data)].lock().insert(data)
    }
    pub fn insert_str(&self, data: &str) -> bool {
        self.insert(data.as_bytes())
    }

    pub fn remove(&self, data: &[u8]) -> bool {
        assert!(data.len() < DOMAIN_MAX_LENGTH);
        self.shards[self.get_location(data)].lock().remove(data)
    }
    pub fn remove_str(&self, data: &str) -> bool {
        self.remove(data.as_bytes())
    }

    pub fn into_iter(self) -> impl Iterator<Item = Vec<u8>> {
        self.shards.into_iter().flat_map(|shard| {
            let shard_iter = std::mem::take(&mut *shard.lock());
            shard_iter.into_iter()
        })
    }

    pub fn into_iter_string(self) -> impl Iterator<Item = String> {
        self.into_iter()
            .filter_map(|element| String::from_utf8(element).ok())
    }

    pub fn into_iter_domains(self) -> impl Iterator<Item = Domain> {
        self.into_iter_string()
            .filter_map(|slice| slice.parse::<Domain>().ok())
    }

    pub fn shrink_to_fit(&self) {
        for shard in self.shards.iter() {
            shard.lock().shrink_to_fit();
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| shard.lock().is_empty())
    }
}

pub struct DomainSetIter<'a> {
    domain_set: &'a DomainSet,
    has_empty_string: bool,
    subset: usize,
    index: usize,
}

impl<'a> DomainSetIter<'a> {
    fn new(domain_set: &'a DomainSet) -> Self {
        Self {
            has_empty_string: domain_set.has_empty_string,
            domain_set,
            subset: 0,
            index: 0,
        }
    }
}

impl<'a> Iterator for DomainSetIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.has_empty_string {
            self.has_empty_string = false;
            Some(&[])
        } else if self.subset < self.domain_set.subsets.len() {
            let subset = &self.domain_set.subsets[self.subset];
            if self.index * (self.subset + 1) < subset.len() {
                let result =
                    &subset[self.index * (self.subset + 1)..(self.index + 1) * (self.subset + 1)];
                self.index += 1;
                Some(result)
            } else {
                self.subset += 1;
                self.index = 0;
                self.next()
            }
        } else {
            None
        }
    }
}

pub struct DomainSetIntoIter {
    domain_set: DomainSet,
    has_empty_string: bool,
    subset: usize,
    index: usize,
}

impl DomainSetIntoIter {
    fn new(domain_set: DomainSet) -> Self {
        Self {
            has_empty_string: domain_set.has_empty_string,
            domain_set,
            subset: 0,
            index: 0,
        }
    }
}

impl Iterator for DomainSetIntoIter {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.has_empty_string {
            self.has_empty_string = false;
            Some(Vec::new())
        } else if self.subset < self.domain_set.subsets.len() {
            let subset = &self.domain_set.subsets[self.subset];
            if self.index * (self.subset + 1) < subset.len() {
                let result = subset
                    [self.index * (self.subset + 1)..(self.index + 1) * (self.subset + 1)]
                    .to_vec();
                self.index += 1;
                Some(result)
            } else {
                self.subset += 1;
                self.index = 0;
                self.next()
            }
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct DomainSet {
    subsets: [Vec<u8>; DOMAIN_MAX_LENGTH],
    has_empty_string: bool,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSet {
    pub fn new() -> Self {
        let mut subsets: [std::mem::MaybeUninit<Vec<u8>>; DOMAIN_MAX_LENGTH] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        for elem in &mut subsets {
            *elem = std::mem::MaybeUninit::new(Vec::new());
        }
        Self {
            subsets: unsafe { std::mem::transmute::<_, _>(subsets) },
            has_empty_string: false,
        }
    }
    fn find_index(&self, data: &[u8]) -> Result<usize, usize> {
        let len = data.len();
        assert!(len != 0);
        let subset = &self.subsets[len - 1];
        assert_eq!(subset.len() % len, 0);
        let chunk_count = subset.len() / len;
        if chunk_count == 0 {
            return Err(0);
        }

        let mut size = chunk_count;
        let mut base = 0;
        while size > 1 {
            let half = size / 2;
            let mid = base + half;
            let slice = &subset[mid * len..(mid + 1) * len];
            let cmp = data.cmp(slice);
            base = if cmp == std::cmp::Ordering::Greater {
                base
            } else {
                mid
            };
            size -= half;
        }
        let slice = &subset[base * len..(base + 1) * len];
        let cmp = data.cmp(slice);
        if cmp == std::cmp::Ordering::Equal {
            Ok(base)
        } else {
            Err(base + (cmp == std::cmp::Ordering::Less) as usize)
        }
    }
    pub fn contains(&self, data: &[u8]) -> bool {
        if data.len() == 0 {
            self.has_empty_string
        } else {
            self.find_index(data).is_ok()
        }
    }
    pub fn contains_str(&self, data: &str) -> bool {
        self.contains(data.as_bytes())
    }

    pub fn insert(&mut self, data: &[u8]) -> bool {
        let len = data.len();
        if len == 0 {
            let old = self.has_empty_string;
            self.has_empty_string = true;
            !self.has_empty_string
        } else if let Err(index) = self.find_index(data) {
            let subset = &mut self.subsets[len - 1];
            let removed: Vec<_> = subset
                .splice(index * len..index * len, data.iter().cloned())
                .collect();
            assert_eq!(removed.len(), 0);
            true
        } else {
            false
        }
    }
    pub fn insert_str(&mut self, data: &str) -> bool {
        self.insert(data.as_bytes())
    }

    pub fn remove(&mut self, data: &[u8]) -> bool {
        let len = data.len();
        if len == 0 {
            let old = self.has_empty_string;
            self.has_empty_string = false;
            self.has_empty_string
        } else if let Ok(index) = self.find_index(data) {
            let subset = &mut self.subsets[len - 1];
            let removed: Vec<_> = subset
                .splice(index * len..(index + 1) * len, std::iter::empty())
                .collect();
            assert_eq!(removed.len(), len);
            true
        } else {
            false
        }
    }

    pub fn remove_str(&mut self, data: &str) -> bool {
        self.remove(data.as_bytes())
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        DomainSetIter::new(self)
    }

    pub fn into_iter(self) -> impl Iterator<Item = Vec<u8>> {
        DomainSetIntoIter::new(self)
    }
    pub fn into_iter_string(self) -> impl Iterator<Item = String> {
        self.into_iter()
            .filter_map(|slice| String::from_utf8(slice).ok())
    }

    pub fn into_iter_domains(self) -> impl Iterator<Item = Domain> {
        self.into_iter_string()
            .filter_map(|slice| slice.parse::<Domain>().ok())
    }

    pub fn shrink_to_fit(&mut self) {
        for subset in self.subsets.iter_mut() {
            subset.shrink_to_fit();
        }
    }

    pub fn len(&self) -> usize {
        self.has_empty_string as usize
            + self
                .subsets
                .iter()
                .enumerate()
                .map(|(len, subset)| subset.len() / (len + 1))
                .sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        !self.has_empty_string && self.subsets.iter().all(|subset| subset.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[quickcheck]
    fn test_sharded_into_iter_string_is_original(mut strings: Vec<String>) {
        let set = DomainSetSharded::default();
        strings.retain(|string| string.len() < DOMAIN_MAX_LENGTH);
        for domain in strings.iter() {
            set.insert_str(&domain);
        }
        let mut generated = set.into_iter_string().collect::<Vec<_>>();
        generated.sort();
        strings.sort();
        strings.dedup();
        assert_eq!(strings, generated);
    }

    #[quickcheck]
    fn test_domain_set_into_iter_string_is_original(mut strings: Vec<String>) {
        let mut set = DomainSet::default();
        strings.retain(|string| string.len() < DOMAIN_MAX_LENGTH);
        for domain in strings.iter() {
            set.insert_str(&domain);
        }
        let mut generated = set.into_iter_string().collect::<Vec<_>>();
        generated.sort();
        strings.sort();
        strings.dedup();
        assert_eq!(strings, generated);
    }

    #[quickcheck]
    fn test_into_iter_is_original(mut slices: Vec<Vec<u8>>) {
        let set = DomainSetSharded::default();
        slices.retain(|string| string.len() < DOMAIN_MAX_LENGTH);
        for domain in slices.iter() {
            set.insert(&domain);
        }
        let mut generated = set.into_iter().collect::<Vec<_>>();
        generated.sort();
        slices.sort();
        slices.dedup();
        assert_eq!(slices, generated);
    }

    #[quickcheck]
    fn test_domain_set_iter_is_original(mut slices: Vec<Vec<u8>>) {
        let mut set = DomainSet::default();
        slices.retain(|string| string.len() < DOMAIN_MAX_LENGTH);
        for domain in slices.iter() {
            set.insert(&domain);
        }
        let mut generated = set.iter().collect::<Vec<_>>();
        generated.sort();
        slices.sort();
        slices.dedup();
        assert_eq!(slices, generated);
    }

    #[test]
    fn test_domain_set_can_have_elements_removed() {
        let mut domains = vec!["google.com", "en.m.wikipedia.org", "example.tk"];
        domains.sort();
        let set = DomainSetSharded::default();
        for domain in domains.iter() {
            set.insert_str(&domain);
        }
        set.insert_str("youtube.com");
        assert_eq!(set.len(), 4);
        assert_eq!(set.contains_str("youtube.com"), true);
        set.remove_str("youtube.com");
        assert_eq!(set.len(), 3);
        assert_eq!(set.contains_str("youtube.com"), false);
        let mut generated = set.into_iter_string().collect::<Vec<_>>();
        generated.sort();
        assert_eq!(domains, generated);
    }

    #[test]
    fn test_domain_set_can_multiple_sizes() {
        let mut domains = vec![
            "",
            "e",
            "ex",
            "exa",
            "exam",
            "examp",
            "exampl",
            "example",
            "example.",
            "example.c",
            "example.co",
            "example.com",
        ];
        domains.sort();
        let set = DomainSetSharded::default();
        for (i, domain) in domains.iter().enumerate() {
            assert_eq!(set.contains_str(&domain), false);
            assert_eq!(set.len(), i);
            set.insert_str(&domain);
            assert_eq!(set.contains_str(&domain), true);
            assert_eq!(set.len(), i + 1);
        }
        let mut generated = set.into_iter_string().collect::<Vec<_>>();
        generated.sort();
        assert_eq!(domains, generated);
    }

    #[test]
    fn test_domain_set_removes_duplicates() {
        let mut domains = vec![
            "google.com",
            "en.m.wikipedia.org",
            "example.tk",
            "google.com",
        ];
        let set = DomainSetSharded::default();
        for domain in domains.iter() {
            set.insert_str(&domain);
        }
        let mut generated = set.into_iter_string().collect::<Vec<_>>();
        generated.sort();
        domains.sort();
        domains.dedup();
        assert_eq!(domains, generated);
    }
}
