use anyhow::ensure;
use regex_lite::Regex;
use serde::{Deserialize, Deserializer, de};
use std::path::{Component, PathBuf};

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    manifest_version: u32,
    pub(super) library: PathBuf,
    pub(super) targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    source: Source,
    pub(super) packages: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_regex")]
    pub(super) process_name_matches: Option<Regex>,
    pub(super) is_main_user: Option<bool>,
    pub(super) is_core_uid: Option<bool>,
    pub(super) is_system_server: Option<bool>,
    pub(super) is_child_zygote: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    Zygote,
}

impl Manifest {
    pub(super) fn parse(input: &str) -> anyhow::Result<Self> {
        let manifest: Self = toml::from_str(input)?;

        ensure!(
            manifest.manifest_version == MANIFEST_VERSION,
            "unsupported manifest version: {}",
            manifest.manifest_version
        );
        ensure!(
            is_safe_relative_path(&manifest.library),
            "invalid library path"
        );
        ensure!(!manifest.targets.is_empty(), "targets must not be empty");

        for (index, target) in manifest.targets.iter().enumerate() {
            if let Some(packages) = &target.packages {
                ensure!(
                    !packages.is_empty(),
                    "targets[{index}].packages must not be empty"
                );
                ensure!(
                    packages.iter().all(|package| !package.is_empty()),
                    "targets[{index}].packages contains an empty package name"
                );
            }
        }

        Ok(manifest)
    }
}

fn deserialize_optional_regex<'de, D>(deserializer: D) -> Result<Option<Regex>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|pattern| Regex::new(&pattern).map_err(de::Error::custom))
        .transpose()
}

fn is_safe_relative_path(path: &std::path::Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_manifest() {
        let manifest = Manifest::parse(
            r#"
                manifest_version = 1
                library = "lib/libexample.so"

                [[targets]]
                source = "zygote"
                packages = ["com.example"]
                process_name_matches = '^com\.example(?::.*)?$'
                is_main_user = false
                is_core_uid = false
                is_system_server = false
                is_child_zygote = false
            "#,
        )
        .unwrap();

        assert_eq!(manifest.library, PathBuf::from("lib/libexample.so"));
        assert_eq!(manifest.targets.len(), 1);
        assert_eq!(
            manifest.targets[0].packages.as_deref(),
            Some(["com.example".into()].as_slice())
        );
        assert!(
            manifest.targets[0]
                .process_name_matches
                .as_ref()
                .unwrap()
                .is_match("com.example:worker")
        );

        for invalid in [
            "manifest_version = 2\nlibrary = 'lib.so'\n[[targets]]\nsource = 'zygote'",
            "manifest_version = 1\nlibrary = '../lib.so'\n[[targets]]\nsource = 'zygote'",
            "manifest_version = 1\nlibrary = 'lib.so'\ntargets = []",
            "manifest_version = 1\nlibrary = 'lib.so'\n[[targets]]\nsource = 'init'",
            "manifest_version = 1\nlibrary = 'lib.so'\n[[targets]]\nsource = 'zygote'\npackages = []",
            "manifest_version = 1\nlibrary = 'lib.so'\n[[targets]]\nsource = 'zygote'\nprocess_name_matches = '['",
            "manifest_version = 1\nlibrary = 'lib.so'\nunknown = true\n[[targets]]\nsource = 'zygote'",
        ] {
            assert!(Manifest::parse(invalid).is_err(), "accepted: {invalid}");
        }
    }
}
