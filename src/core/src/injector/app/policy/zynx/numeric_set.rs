use anyhow::ensure;
use serde::{Deserialize, Deserializer, de};
use std::ops::RangeInclusive;
use std::str::FromStr;

#[derive(Debug)]
pub(super) struct NumericSet(Vec<RangeInclusive<u32>>);

impl NumericSet {
    pub(super) fn contains(&self, value: u32) -> bool {
        self.0.iter().any(|range| range.contains(&value))
    }
}

impl FromStr for NumericSet {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> anyhow::Result<Self> {
        let mut ranges = Vec::new();

        for item in input.split(',') {
            let item = item.trim();
            let (l, r) = if let Some((l, r)) = item.split_once('-') {
                let l = l.trim();
                let r = r.trim();

                ensure!(
                    !l.is_empty() || !r.is_empty(),
                    "use an omitted field to match all values"
                );

                (
                    if l.is_empty() { 0 } else { l.parse::<u32>()? },
                    if r.is_empty() {
                        u32::MAX
                    } else {
                        r.parse::<u32>()?
                    },
                )
            } else {
                let value = item.parse::<u32>()?;

                (value, value)
            };

            ensure!(l <= r, "reversed numeric range: {item}");
            ranges.push(l..=r);
        }

        Ok(Self(ranges))
    }
}

impl<'de> Deserialize<'de> for NumericSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::NumericSet;

    #[test]
    fn matches_single_values_unions_and_inclusive_bounds() {
        let set: NumericSet = " 0-9999 , +12000, 4294967295 ".parse().unwrap();
        for value in [0, 9999, 12000, u32::MAX] {
            assert!(set.contains(value));
        }
        for value in [10000, 11999, 12001] {
            assert!(!set.contains(value));
        }
        let lower: NumericSet = "10000-".parse().unwrap();
        assert!(!lower.contains(9999));
        assert!(lower.contains(10000));
        assert!(lower.contains(u32::MAX));
        let upper: NumericSet = "-9999".parse().unwrap();
        assert!(upper.contains(0));
        assert!(upper.contains(9999));
        assert!(!upper.contains(10000));
    }

    #[test]
    fn rejects_malformed_numeric_sets() {
        for input in [
            "",
            " ",
            "*",
            "*-*",
            "-",
            " - ",
            "1-*",
            "*-9999",
            "9-1",
            "1,,2",
            "1,",
            ",1",
            "1-2-3",
            "4294967296",
            "0-4294967296",
            "0x10",
            "1 2",
        ] {
            assert!(input.parse::<NumericSet>().is_err(), "accepted {input:?}");
        }
    }
}
