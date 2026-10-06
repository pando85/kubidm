//! `utils.rs` - the projects kitchen junk drawer.

use crate::prelude::*;
use hashbrown::HashSet;
use rand::{
    distr::{Distribution, Uniform},
    rng, Rng, RngExt,
};
use std::ops::Range;
use unicode_segmentation::UnicodeSegmentation;

#[derive(Debug)]
pub struct DistinctAlpha;

pub type Sid = [u8; 4];

pub fn uuid_to_gid_u32(u: Uuid) -> u32 {
    let b_ref = u.as_bytes();
    let mut x: [u8; 4] = [0; 4];
    x.clone_from_slice(&b_ref[12..16]);
    u32::from_be_bytes(x)
}

fn uuid_from_u64_u32(a: u64, b: u32, sid: Sid) -> Uuid {
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&a.to_be_bytes());
    v.extend_from_slice(&b.to_be_bytes());
    v.extend_from_slice(&sid);

    #[allow(clippy::expect_used)]
    uuid::Builder::from_slice(v.as_slice())
        .expect("invalid slice for uuid builder")
        .into_uuid()
}

pub fn uuid_from_duration(d: Duration, sid: Sid) -> Uuid {
    uuid_from_u64_u32(d.as_secs(), d.subsec_nanos(), sid)
}

pub(crate) fn password_from_random_len(len: u32) -> String {
    rng()
        .sample_iter(&DistinctAlpha)
        .take(len as usize)
        .collect::<String>()
}

pub fn password_from_random() -> String {
    password_from_random_len(48)
}

pub fn backup_code_from_random() -> HashSet<String> {
    (0..8).map(|_| readable_password_from_random()).collect()
}

pub fn readable_password_from_random() -> String {
    // 2^112 bits, means we need at least 55^20 to have as many bits of entropy.
    // this leads us to 4 groups of 5 to create 55^20
    let mut trng = rng();
    format!(
        "{}-{}-{}-{}",
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
        (&mut trng)
            .sample_iter(&DistinctAlpha)
            .take(5)
            .collect::<String>(),
    )
}

impl Distribution<char> for DistinctAlpha {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        static GEN_ASCII_STR_CHARSET: &[u8; 31] = b"abcdefghjkpqrstuvwxyz0123456789";

        // this needs to handle the error, maybe?
        // - This represents a failure of the RNG at a critical level, meaning we can not
        //   continue.
        #[allow(clippy::expect_used)]
        let range = Uniform::new(0, GEN_ASCII_STR_CHARSET.len())
            .expect("CRITICAL: Failed to build a uniform random number generator during character generation.");

        let n = range.sample(rng);
        debug_assert!(n < GEN_ASCII_STR_CHARSET.len());
        // n must lay within range due to the promises of the rand crate.
        #[allow(clippy::indexing_slicing)]
        let c = GEN_ASCII_STR_CHARSET[n] as char;
        c
    }
}

/// This iterates over groups of graphemes. Each `window` size is how many
/// graphemes to return at a time. For example, a window of `1` on the string
/// "abc" will return "a", "b", "c". A window of `2' will return "ab", "bc".
pub(crate) struct GraphemeClusterIter<'a> {
    value: &'a str,
    char_bounds: Vec<usize>,
    window: usize,
    range: Range<usize>,
}

impl<'a> GraphemeClusterIter<'a> {
    pub fn new(value: &'a str, window: usize) -> Self {
        let char_bounds = if value.len() < window {
            Vec::with_capacity(0)
        } else {
            value
                .grapheme_indices(true)
                .map(|(idx, _grapheme)| idx)
                .chain(std::iter::once(value.len()))
                .collect::<Vec<_>>()
        };

        let window_max = char_bounds.len().saturating_sub(window);
        let range = 0..window_max;

        GraphemeClusterIter {
            value,
            char_bounds,
            window,
            range,
        }
    }
}

impl<'a> Iterator for GraphemeClusterIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        // range is calculated as 0 to window_max, where
        // window_max == char_bounds.len() - window. This
        // means that provided an item is yielded, then it
        // will always be inbounds.
        self.range.next().map(|idx| {
            debug_assert!(idx < self.char_bounds.len());
            debug_assert!(idx + self.window < self.char_bounds.len());
            #[allow(clippy::indexing_slicing)]
            let min = self.char_bounds[idx];
            #[allow(clippy::indexing_slicing)]
            let max = self.char_bounds[idx + self.window];
            &self.value[min..max]
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let clusters = self.char_bounds.len().saturating_sub(self.window);
        (clusters, Some(clusters))
    }
}

pub(crate) fn trigraph_iter(value: &str) -> impl Iterator<Item = &str> {
    GraphemeClusterIter::new(value, 3)
        .chain(GraphemeClusterIter::new(value, 2))
        .chain(GraphemeClusterIter::new(value, 1))
}

pub(crate) fn utf8_len(value: &str) -> usize {
    value.graphemes(true).count()
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::time::Duration;

    use crate::utils::{utf8_len, uuid_from_duration, uuid_to_gid_u32, GraphemeClusterIter};

    #[test]
    fn test_utils_uuid_from_duration() {
        let u1 = uuid_from_duration(Duration::from_secs(1), [0xff; 4]);
        assert_eq!(
            "00000000-0000-0001-0000-0000ffffffff",
            u1.as_hyphenated().to_string()
        );

        let u2 = uuid_from_duration(Duration::from_secs(1000), [0xff; 4]);
        assert_eq!(
            "00000000-0000-03e8-0000-0000ffffffff",
            u2.as_hyphenated().to_string()
        );
    }

    #[test]
    fn test_utils_uuid_to_gid_u32() {
        let u1 = uuid!("00000000-0000-0001-0000-000000000000");
        let r1 = uuid_to_gid_u32(u1);
        assert_eq!(r1, 0);

        let u2 = uuid!("00000000-0000-0001-0000-0000ffffffff");
        let r2 = uuid_to_gid_u32(u2);
        assert_eq!(r2, 0xffffffff);

        let u3 = uuid!("00000000-0000-0001-0000-ffff12345678");
        let r3 = uuid_to_gid_u32(u3);
        assert_eq!(r3, 0x12345678);
    }

    #[test]
    fn test_utils_grapheme_cluster_iter() {
        let d = "❤️🧡💛💚💙💜";

        let gc_expect = vec!["❤\u{fe0f}", "🧡", "💛", "💚", "💙", "💜"];
        let gc_iter = GraphemeClusterIter::new(d, 1);
        assert_eq!(gc_iter.size_hint().0, 6);
        let gc: Vec<_> = gc_iter.collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["❤\u{fe0f}🧡", "🧡💛", "💛💚", "💚💙", "💙💜"];
        let gc_iter = GraphemeClusterIter::new(d, 2);
        assert_eq!(gc_iter.size_hint().0, 5);
        let gc: Vec<_> = gc_iter.collect();
        assert_eq!(gc, gc_expect);

        let gc_expect = vec!["❤\u{fe0f}🧡💛", "🧡💛💚", "💛💚💙", "💚💙💜"];
        let gc_iter = GraphemeClusterIter::new(d, 3);
        assert_eq!(gc_iter.size_hint().0, 4);
        let gc: Vec<_> = gc_iter.collect();
        assert_eq!(gc, gc_expect);
    }

    #[test]
    fn test_utils_grapheme_len() {
        assert_eq!(utf8_len(""), 0);
        assert_eq!(utf8_len("a"), 1);
        assert_eq!(utf8_len("ab"), 2);
        assert_eq!(utf8_len("abcdef"), 6);
        assert_eq!(utf8_len("🤷"), 1);
        assert_eq!(utf8_len("🤷🏿"), 1);
    }

    #[test]
    fn test_utils_grapheme_cluster_iter_empty() {
        let gc: Vec<_> = GraphemeClusterIter::new("", 1).collect();
        assert!(gc.is_empty());
    }

    #[test]
    fn test_utils_grapheme_cluster_iter_window_larger_than_string() {
        let gc: Vec<_> = GraphemeClusterIter::new("abc", 10).collect();
        assert!(gc.is_empty());
    }

    #[test]
    fn test_utils_grapheme_cluster_iter_simple_ascii() {
        let d = "abc";
        let gc: Vec<_> = GraphemeClusterIter::new(d, 1).collect();
        assert_eq!(gc, vec!["a", "b", "c"]);

        let gc: Vec<_> = GraphemeClusterIter::new(d, 2).collect();
        assert_eq!(gc, vec!["ab", "bc"]);

        let gc: Vec<_> = GraphemeClusterIter::new(d, 3).collect();
        assert_eq!(gc, vec!["abc"]);
    }

    #[test]
    fn test_utils_grapheme_cluster_iter_size_hint() {
        let iter = GraphemeClusterIter::new("abc", 1);
        assert_eq!(iter.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_utils_trigraph_iter() {
        use crate::utils::trigraph_iter;

        let clusters: Vec<_> = trigraph_iter("abc").collect();
        assert_eq!(clusters, vec!["abc", "ab", "bc", "a", "b", "c"]);
    }

    #[test]
    fn test_utils_trigraph_iter_short_string() {
        use crate::utils::trigraph_iter;

        let clusters: Vec<_> = trigraph_iter("ab").collect();
        assert_eq!(clusters, vec!["ab", "a", "b"]);
    }

    #[test]
    fn test_utils_password_from_random_len() {
        use crate::utils::password_from_random_len;

        let pw = password_from_random_len(10);
        assert_eq!(pw.len(), 10);
        let allowed = "abcdefghjkpqrstuvwxyz0123456789";
        for c in pw.chars() {
            assert!(allowed.contains(c), "Invalid character: {}", c);
        }
    }

    #[test]
    fn test_utils_password_from_random() {
        use crate::utils::password_from_random;

        let pw = password_from_random();
        assert_eq!(pw.len(), 48);
    }

    #[test]
    fn test_utils_readable_password_from_random() {
        use crate::utils::readable_password_from_random;

        let pw = readable_password_from_random();
        assert_eq!(pw.len(), 23);
        assert_eq!(pw.chars().filter(|&c| c == '-').count(), 3);
        let parts: Vec<&str> = pw.split('-').collect();
        assert_eq!(parts.len(), 4);
        for part in &parts {
            assert_eq!(part.len(), 5);
        }
    }

    #[test]
    fn test_utils_backup_code_from_random() {
        use crate::utils::backup_code_from_random;

        let codes = backup_code_from_random();
        assert_eq!(codes.len(), 8);
        for code in &codes {
            assert_eq!(code.len(), 23);
        }
    }

    #[test]
    fn test_utils_distinct_alpha_distribution() {
        use crate::utils::DistinctAlpha;
        use rand::distr::Distribution;
        use rand::rng;

        let allowed = "abcdefghjkpqrstuvwxyz0123456789";
        let mut rng = rng();
        for _ in 0..1000 {
            let c = DistinctAlpha.sample(&mut rng);
            assert!(
                allowed.contains(c),
                "DistinctAlpha produced invalid character: {}",
                c
            );
        }
    }
}
