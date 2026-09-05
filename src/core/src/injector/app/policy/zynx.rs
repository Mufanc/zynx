use crate::android::{FIRST_APPLICATION_UID, PER_USER_RANGE};
use crate::injector::app::policy::EmbryoCheckArgs;
use regex_lite::Regex;
use serde::{Deserialize, Deserializer, de};
use std::path::{Component, Path, PathBuf};
use validator::{Validate, ValidationError};

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = "validate_manifest"))]
pub(super) struct Manifest {
    #[validate(custom(function = "validate_manifest_version"))]
    manifest_version: u32,
    #[validate(custom(function = "validate_library"))]
    pub(super) library: PathBuf,
    #[validate(nested)]
    pub(super) targets: Vec<Target>,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    source: Source,
    #[validate(length(min = 1), custom(function = "validate_package_names"))]
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum MatchResult {
    Match,
    MoreInfo,
    NoMatch,
}

impl Manifest {
    pub(super) fn parse(input: &str) -> anyhow::Result<Self> {
        let manifest: Self = toml::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub(super) fn matches(&self, args: &EmbryoCheckArgs) -> MatchResult {
        let mut more_info = false;

        for target in &self.targets {
            match target.matches(args) {
                MatchResult::Match => return MatchResult::Match,
                MatchResult::MoreInfo => more_info = true,
                MatchResult::NoMatch => {}
            }
        }

        if more_info {
            MatchResult::MoreInfo
        } else {
            MatchResult::NoMatch
        }
    }
}

impl Target {
    fn matches(&self, args: &EmbryoCheckArgs) -> MatchResult {
        let process_uid = args.uid.as_raw();
        let is_main_user = process_uid / PER_USER_RANGE == 0;
        let is_core_uid = process_uid % PER_USER_RANGE < FIRST_APPLICATION_UID;

        if !matches_optional_bool(self.is_main_user, is_main_user)
            || !matches_optional_bool(self.is_core_uid, is_core_uid)
            || !matches_optional_bool(self.is_system_server, args.is_system_server)
            || !matches_optional_bool(self.is_child_zygote, args.is_child_zygote)
        {
            return MatchResult::NoMatch;
        }

        if let Some(packages) = &self.packages
            && !args.package_info.as_deref().is_some_and(|package_info| {
                package_info
                    .iter()
                    .any(|package| packages.contains(&package.name))
            })
        {
            return MatchResult::NoMatch;
        }

        match (&self.process_name_matches, args) {
            (None, _) => MatchResult::Match,
            (Some(_), EmbryoCheckArgs::Fast(_)) => MatchResult::MoreInfo,
            (Some(regex), EmbryoCheckArgs::Slow(args))
                if args
                    .nice_name
                    .as_deref()
                    .is_some_and(|name| regex.is_match(name)) =>
            {
                MatchResult::Match
            }
            (Some(_), EmbryoCheckArgs::Slow(_)) => MatchResult::NoMatch,
        }
    }
}

fn matches_optional_bool(expected: Option<bool>, actual: bool) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), ValidationError> {
    if manifest.targets.is_empty() {
        Err(ValidationError::new("empty_targets"))
    } else {
        Ok(())
    }
}

fn validate_manifest_version(version: u32) -> Result<(), ValidationError> {
    if version == MANIFEST_VERSION {
        Ok(())
    } else {
        Err(ValidationError::new("unsupported_manifest_version"))
    }
}

fn validate_library(path: &Path) -> Result<(), ValidationError> {
    if is_safe_relative_path(path) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_library_path"))
    }
}

fn validate_package_names(packages: &[String]) -> Result<(), ValidationError> {
    if packages.iter().all(|package| !package.is_empty()) {
        Ok(())
    } else {
        Err(ValidationError::new("empty_package_name"))
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

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::packages::PackageInfo;
    use nix::unistd::{Gid, Uid};
    use std::sync::Arc;

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
            "manifest_version = 1\nlibrary = 'lib.so'\n[[targets]]\nsource = 'zygote'\npackages = ['']",
            "manifest_version = 1\nlibrary = 'lib.so'\n[[targets]]\nsource = 'zygote'\nprocess_name_matches = '['",
            "manifest_version = 1\nlibrary = 'lib.so'\nunknown = true\n[[targets]]\nsource = 'zygote'",
        ] {
            assert!(Manifest::parse(invalid).is_err(), "accepted: {invalid}");
        }
    }

    #[test]
    fn matches_targets_in_two_phases() {
        let manifest = Manifest::parse(
            r#"
                manifest_version = 1
                library = "lib.so"

                [[targets]]
                source = "zygote"
                packages = ["com.example"]
                process_name_matches = '^com\.example(?::.*)?$'
                is_main_user = false
                is_core_uid = false

                [[targets]]
                source = "zygote"
                is_system_server = true
            "#,
        )
        .unwrap();

        let package_info: Arc<[PackageInfo]> = vec![PackageInfo {
            name: "com.example".into(),
            uid: Uid::from_raw(10_123),
            debuggable: false,
            data_dir: "/data/user/0/com.example".into(),
            seinfo: "default".into(),
            gids: Vec::new(),
        }]
        .into();
        let fast = EmbryoCheckArgs::new_fast(
            Uid::from_raw(1_010_123),
            Gid::from_raw(1_010_123),
            false,
            false,
            Some(package_info),
        );

        assert_eq!(manifest.matches(&fast), MatchResult::MoreInfo);
        assert_eq!(
            manifest.matches(&fast.into_slow(Some("com.example:worker".into()), None)),
            MatchResult::Match
        );

        let system_server =
            EmbryoCheckArgs::new_fast(Uid::from_raw(1000), Gid::from_raw(1000), true, false, None);
        assert_eq!(manifest.matches(&system_server), MatchResult::Match);

        let unmatched = EmbryoCheckArgs::new_fast(
            Uid::from_raw(10_123),
            Gid::from_raw(10_123),
            false,
            false,
            None,
        );
        assert_eq!(manifest.matches(&unmatched), MatchResult::NoMatch);
    }
}
