use super::numeric_set::NumericSet;
use super::rule::{InitConditions, InjectionRule, ModuleManifest, ZygoteConditions, ZygoteFilter};
use crate::injector::app::policy::filter::ExternalFilter;
use anyhow::ensure;
use regex_lite::Regex;
use serde::{Deserialize, Deserializer, de};
use std::path::{Component, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestConfig {
    manifest_version: u32,
    #[serde(default)]
    inject: Vec<InjectionRuleConfig>,
    zygisk: Option<ZygiskConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum InjectionRuleConfig {
    Zygote {
        library: PathBuf,
        filter: ZygoteFilterConfig,
    },
    Init {
        library: PathBuf,
        filter: InitFilterConfig,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZygiskConfig {
    filter: ZygoteFilterConfig,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ZygoteFilterConfig {
    Static(ZygoteConditionsConfig),
    Stdio {
        path: PathBuf,
        #[serde(default)]
        args: Vec<String>,
    },
    SocketFile {
        path: PathBuf,
    },
    UnixAbstract {
        prefix: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum InitFilterConfig {
    Static(InitConditionsConfig),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZygoteConditionsConfig {
    uid: Option<NumericSet>,
    user_id: Option<NumericSet>,
    packages: Option<Vec<String>>,
    process_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_regex")]
    process_name_matches: Option<Regex>,
    is_system_server: Option<bool>,
    is_child_zygote: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitConditionsConfig {
    path: Option<PathBuf>,
    name: Option<String>,
    uid: Option<NumericSet>,
    user_id: Option<NumericSet>,
}

impl ModuleManifest {
    pub(super) fn parse(input: &str) -> anyhow::Result<Self> {
        let manifest: ManifestConfig = toml::from_str(input)?;

        manifest.validate()?;

        Ok(manifest.into_manifest())
    }
}

impl ManifestConfig {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.manifest_version == 2,
            "only manifest_version = 2 is supported"
        );
        ensure!(
            !self.inject.is_empty() || self.zygisk.is_some(),
            "manifest must contain at least one injection rule or a zygisk section"
        );

        for rule in &self.inject {
            rule.validate()?;
        }

        if let Some(zygisk) = &self.zygisk {
            zygisk.validate()?;
        }

        Ok(())
    }

    fn into_manifest(self) -> ModuleManifest {
        ModuleManifest {
            rules: self
                .inject
                .into_iter()
                .map(InjectionRuleConfig::into_rule)
                .collect(),
            zygisk: self.zygisk.map(|zygisk| zygisk.filter.into_filter()),
        }
    }
}

impl ZygiskConfig {
    fn validate(&self) -> anyhow::Result<()> {
        self.filter.validate()
    }
}

impl InjectionRuleConfig {
    fn validate(&self) -> anyhow::Result<()> {
        let library = match self {
            Self::Zygote { library, .. } | Self::Init { library, .. } => library,
        };

        ensure!(
            !library.as_os_str().is_empty()
                && library
                    .components()
                    .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
            "library must be a relative path without '..': {}",
            library.display()
        );
        ensure!(
            library
                .components()
                .any(|part| matches!(part, Component::Normal(_))),
            "library path must name a file"
        );

        match self {
            Self::Zygote { filter, .. } => filter.validate(),
            Self::Init { filter, .. } => filter.validate(),
        }
    }

    fn into_rule(self) -> InjectionRule {
        let normalize = |library: PathBuf| {
            library
                .components()
                .filter_map(|part| match part {
                    Component::Normal(name) => Some(name),
                    _ => None,
                })
                .collect()
        };

        match self {
            Self::Zygote { library, filter } => InjectionRule::Zygote {
                library: normalize(library),
                filter: filter.into_filter(),
            },
            Self::Init { library, filter } => InjectionRule::Init {
                library: normalize(library),
                conditions: filter.into_conditions(),
            },
        }
    }
}

impl ZygoteFilterConfig {
    fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Static(conditions) => conditions.validate(),
            _ => Ok(()),
        }
    }

    fn into_filter(self) -> ZygoteFilter {
        match self {
            Self::Static(conditions) => ZygoteFilter::Static(conditions.into_conditions()),
            Self::Stdio { path, args } => {
                ZygoteFilter::External(ExternalFilter::Stdio { path, args })
            }
            Self::SocketFile { path } => {
                ZygoteFilter::External(ExternalFilter::SocketFile { path })
            }
            Self::UnixAbstract { prefix } => {
                ZygoteFilter::External(ExternalFilter::UnixAbstract { prefix })
            }
        }
    }
}

impl InitFilterConfig {
    fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Static(conditions) => conditions.validate(),
        }
    }

    fn into_conditions(self) -> InitConditions {
        match self {
            Self::Static(conditions) => conditions.into_conditions(),
        }
    }
}

impl ZygoteConditionsConfig {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.uid.is_some()
                || self.user_id.is_some()
                || self.packages.is_some()
                || self.process_name.is_some()
                || self.process_name_matches.is_some()
                || self.is_system_server.is_some()
                || self.is_child_zygote.is_some(),
            "static filter requires at least one condition"
        );

        if let Some(packages) = &self.packages {
            ensure!(
                !packages.is_empty() && packages.iter().all(|package| !package.is_empty()),
                "packages must contain at least one nonempty package name"
            );
        }

        ensure!(
            self.process_name.is_none() || self.process_name_matches.is_none(),
            "process_name and process_name_matches cannot both be set"
        );

        Ok(())
    }

    fn into_conditions(self) -> ZygoteConditions {
        ZygoteConditions {
            uid: self.uid,
            user_id: self.user_id,
            packages: self.packages,
            process_name: self.process_name,
            process_name_matches: self.process_name_matches,
            is_system_server: self.is_system_server,
            is_child_zygote: self.is_child_zygote,
        }
    }
}

impl InitConditionsConfig {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.path.is_some() != self.name.is_some(),
            "source = init requires exactly one of path or name"
        );

        if let Some(path) = &self.path {
            ensure!(
                path.is_absolute() && path.file_name().is_some(),
                "path must be an absolute executable path"
            );
        }

        if let Some(name) = &self.name {
            ensure!(
                !name.is_empty()
                    && !matches!(name.as_str(), "." | "..")
                    && !name.contains(['/', '\0']),
                "name must be a nonempty exec basename without '/' or NUL"
            );
        }

        Ok(())
    }

    fn into_conditions(self) -> InitConditions {
        InitConditions {
            path: self.path,
            name: self.name,
            uid: self.uid,
            user_id: self.user_id,
        }
    }
}

fn deserialize_optional_regex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Regex>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|pattern| Regex::new(&pattern).map_err(de::Error::custom))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::packages::PackageInfo;
    use crate::injector::app::policy::ProcessInfo;
    use nix::unistd::{Gid, Uid};
    use std::sync::Arc;

    fn zygote_filter(rule: &InjectionRule) -> &ZygoteFilter {
        let InjectionRule::Zygote { filter, .. } = rule else {
            panic!("expected zygote rule");
        };
        filter
    }

    fn process(uid: u32) -> ProcessInfo {
        ProcessInfo {
            uid: Uid::from_raw(uid),
            gid: Gid::from_raw(uid),
            is_system_server: false,
            is_child_zygote: false,
            package_info: None,
            nice_name: Some("com.example".into()),
            app_data_dir: None,
        }
    }

    fn rule(source: &str, fields: &str) -> anyhow::Result<ModuleManifest> {
        ModuleManifest::parse(&format!(
            "manifest_version = 2\n[[inject]]\nsource = '{source}'\nlibrary = './lib.so'\n[inject.filter]\ntype = 'static'\n{fields}"
        ))
    }

    #[tokio::test]
    async fn shares_static_and_external_filter_parsing_between_zygisk_and_inject() {
        for fields in [
            "type = 'static'\nuid = '10000-'\nuser_id = '0'",
            "type = 'static'\nprocess_name = 'com.example'",
            "type = 'static'\nprocess_name_matches = '^com\\.example$'",
            "type = 'static'\nis_system_server = false\nis_child_zygote = false",
            "type = 'stdio'\npath = '/bin/filter'",
            "type = 'socket_file'\npath = '/data/filter.sock'",
            "type = 'unix_abstract'\nprefix = 'example'",
        ] {
            let text = format!(
                "manifest_version = 2\n[zygisk.filter]\n{fields}\n[[inject]]\nsource = 'zygote'\nlibrary = 'lib.so'\n[inject.filter]\n{fields}"
            );
            let manifest = ModuleManifest::parse(&text).unwrap();
            let zygisk = manifest.zygisk.as_ref().unwrap();
            if matches!(zygisk, ZygoteFilter::Static(_)) {
                for uid in [0, 10123, 110123] {
                    assert_eq!(
                        zygisk.check(&process(uid)).await.unwrap(),
                        zygote_filter(&manifest.rules[0])
                            .check(&process(uid))
                            .await
                            .unwrap()
                    );
                }
            } else {
                assert!(matches!(
                    zygote_filter(&manifest.rules[0]),
                    ZygoteFilter::External(_)
                ));
            }
        }
        let manifest = ModuleManifest::parse(
            "manifest_version = 2\n[zygisk.filter]\ntype = 'static'\nuid = '0'",
        )
        .unwrap();
        assert!(manifest.rules.is_empty());
        assert!(manifest.zygisk.unwrap().check(&process(0)).await.unwrap());
        let manifest = rule("zygote", "uid = '0'").unwrap();
        assert!(manifest.zygisk.is_none());
        assert!(
            zygote_filter(&manifest.rules[0])
                .check(&process(0))
                .await
                .unwrap()
        );
    }

    #[test]
    fn validates_the_entire_configuration_from_the_manifest_entry_point() {
        let valid = "manifest_version = 2\n[[inject]]\nsource = 'zygote'\nlibrary = 'lib.so'\n[inject.filter]\ntype = 'static'\nuid = '10123'";
        let config: ManifestConfig = toml::from_str(valid).unwrap();
        config.validate().unwrap();
        let manifest = config.into_manifest();
        assert_eq!(manifest.rules.len(), 1);
        for (text, expected) in [
            (
                "manifest_version = 3\ninject = []".to_string(),
                "only manifest_version",
            ),
            (
                "manifest_version = 2\ninject = []".to_string(),
                "at least one injection rule",
            ),
            (
                format!(
                    "{valid}\n[[inject]]\nsource = 'zygote'\nlibrary = '../lib.so'\n[inject.filter]\ntype = 'static'\nuid = '10123'"
                ),
                "relative path",
            ),
            (
                format!(
                    "{valid}\n[[inject]]\nsource = 'zygote'\nlibrary = 'other.so'\n[inject.filter]\ntype = 'static'"
                ),
                "at least one condition",
            ),
            (
                format!("{valid}\n[zygisk.filter]\ntype = 'static'"),
                "at least one condition",
            ),
            (
                format!(
                    "{valid}\n[[inject]]\nsource = 'init'\nlibrary = 'service.so'\n[inject.filter]\ntype = 'static'\npath = '/bin/service'\nname = 'service'"
                ),
                "exactly one of path or name",
            ),
        ] {
            let config: ManifestConfig = toml::from_str(&text).unwrap();
            let error = config.validate().unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }

    #[test]
    fn rejects_empty_static_filters_and_accepts_each_explicit_condition() {
        for text in [
            "manifest_version = 2\n[zygisk.filter]\ntype = 'static'",
            "manifest_version = 2\n[[inject]]\nsource = 'zygote'\nlibrary = 'lib.so'\n[inject.filter]\ntype = 'static'",
        ] {
            let error = ModuleManifest::parse(text).unwrap_err();
            assert!(
                error.to_string().contains("at least one condition"),
                "{error:#}"
            );
        }
        for fields in [
            "uid = '10123'",
            "user_id = '0'",
            "packages = ['com.example']",
            "process_name = 'com.example'",
            "process_name_matches = '^com\\.example$'",
            "is_system_server = false",
            "is_child_zygote = false",
        ] {
            rule("zygote", fields).unwrap();
        }
        for fields in ["path = '/bin/service'", "name = 'service'"] {
            rule("init", fields).unwrap();
        }
    }

    #[test]
    fn requires_typed_filters_and_rejects_fields_outside_their_variant() {
        for section in ["zygisk", "inject"] {
            let header = if section == "inject" {
                "[[inject]]\nsource = 'zygote'\nlibrary = 'lib.so'"
            } else {
                "[zygisk]"
            };
            for fields in [
                "",
                "uid = '10000-'",
                "filter = {}",
                "filter = { type = 'unknown' }",
                "filter = { type = 'static' }\nunknown = true",
            ] {
                let text = format!("manifest_version = 2\n{header}\n{fields}");
                assert!(ModuleManifest::parse(&text).is_err(), "accepted {text}");
            }
            for fields in [
                "",
                "type = 'unknown'",
                "type = 'static'\nunknown = true",
                "type = 'stdio'",
                "type = 'static'\nargs = []",
                "type = 'stdio'\npath = '/bin/filter'\nuid = '10000-'",
                "type = 'socket_file'\npath = '/data/filter.sock'\npackages = ['com.example']",
                "type = 'unix_abstract'\nprefix = 'example'\nprocess_name = 'com.example'",
                "type = 'static'\nfilter = { type = 'stdio', path = '/bin/filter' }",
            ] {
                let text = format!("manifest_version = 2\n{header}\n[{section}.filter]\n{fields}");
                assert!(ModuleManifest::parse(&text).is_err(), "accepted {text}");
            }
        }
        for fields in [
            "library = 'zygisk/arm64-v8a.so'",
            "source = 'zygote'",
            "path = '/bin/service'",
            "name = 'service'",
        ] {
            let text = format!(
                "manifest_version = 2\n[zygisk]\n{fields}\n[zygisk.filter]\ntype = 'static'"
            );
            assert!(ModuleManifest::parse(&text).is_err());
        }
    }

    #[tokio::test]
    async fn matches_normalized_libraries_numeric_conditions_packages_names_and_flags() {
        let manifest = rule("zygote", "uid = '110000-119999,210123'\nuser_id = '1'").unwrap();
        assert_eq!(manifest.rules[0].library(), &PathBuf::from("lib.so"));
        for uid in [110000, 110123, 119999] {
            assert!(
                zygote_filter(&manifest.rules[0])
                    .check(&process(uid))
                    .await
                    .unwrap()
            );
        }
        for uid in [109999, 120000, 210123] {
            assert!(
                !zygote_filter(&manifest.rules[0])
                    .check(&process(uid))
                    .await
                    .unwrap()
            );
        }
        let manifest = rule("zygote", "packages = ['com.other', 'com.example']\nprocess_name = 'com.example'\nis_system_server = false\nis_child_zygote = false").unwrap();
        let filter = zygote_filter(&manifest.rules[0]);
        let mut info = process(10123);
        assert!(!filter.check(&info).await.unwrap());
        info.package_info = Some(Arc::from(vec![PackageInfo {
            name: "com.example".into(),
            app_id: info.uid.as_raw() % crate::android::PER_USER_RANGE,
            debuggable: false,
            data_dir: "/data/user/0/com.example".into(),
            seinfo: "default".into(),
            gids: Vec::new(),
        }]));
        assert!(filter.check(&info).await.unwrap());
        info.is_system_server = true;
        assert!(!filter.check(&info).await.unwrap());
        info.is_system_server = false;
        info.is_child_zygote = true;
        assert!(!filter.check(&info).await.unwrap());
        let manifest = rule("zygote", "process_name_matches = 'example'").unwrap();
        info.nice_name = Some("com.example:worker".into());
        assert!(
            zygote_filter(&manifest.rules[0])
                .check(&info)
                .await
                .unwrap()
        );
        info.nice_name = None;
        assert!(
            !zygote_filter(&manifest.rules[0])
                .check(&info)
                .await
                .unwrap()
        );
    }

    #[test]
    fn rejects_fields_from_other_sources_during_deserialization() {
        for (source, fields) in [
            ("zygote", "path = '/bin/service'"),
            ("zygote", "name = 'service'"),
            ("init", "name = 'service'\npackages = ['com.example']"),
            ("init", "name = 'service'\nprocess_name = 'com.example'"),
            ("init", "name = 'service'\nprocess_name_matches = 'example'"),
            ("init", "name = 'service'\nis_system_server = false"),
            ("init", "name = 'service'\nis_child_zygote = false"),
        ] {
            let text = format!(
                "manifest_version = 2\n[[inject]]\nsource = '{source}'\nlibrary = 'lib.so'\n[inject.filter]\ntype = 'static'\n{fields}"
            );
            assert!(
                toml::from_str::<ManifestConfig>(&text).is_err(),
                "accepted {text}"
            );
        }
        for fields in ["path = '/bin/service'", "name = 'service'"] {
            let text = format!("manifest_version = 2\n[zygisk.filter]\ntype = 'static'\n{fields}");
            assert!(
                toml::from_str::<ManifestConfig>(&text).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn parses_init_static_filters_and_rejects_invalid_source_conditions() {
        for fields in [
            "path = '/vendor/bin/service'\nuid = '-9999'\nuser_id = '0'",
            "name = 'service'",
        ] {
            let manifest = rule("init", fields).unwrap();
            let InjectionRule::Init { conditions, .. } = &manifest.rules[0] else {
                panic!("expected static");
            };
            assert!(conditions.path.is_some() != conditions.name.is_some());
        }
        for fields in [
            "",
            "path = ''",
            "path = 'vendor/bin/service'",
            "path = '/'",
            "path = '/vendor/bin/service'\nname = 'service'",
            "name = ''",
            "name = '.'",
            "name = '..'",
            "name = '/vendor/bin/service'",
            "name = './service'",
            "name = 'service/'",
            r#"name = "service\u0000""#,
            "name = 'service'\npackages = ['com.example']",
            "name = 'service'\nprocess_name = 'service'",
            "name = 'service'\nprocess_name_matches = 'service'",
            "name = 'service'\nis_system_server = false",
            "name = 'service'\nis_child_zygote = false",
        ] {
            assert!(rule("init", fields).is_err(), "accepted {fields}");
        }
        for fields in ["path = '/bin/service'", "name = 'service'"] {
            assert!(rule("zygote", fields).is_err());
        }
        for fields in [
            "type = 'stdio'\npath = '/bin/filter'",
            "type = 'socket_file'\npath = '/tmp/filter'",
            "type = 'unix_abstract'\nprefix = 'example'",
        ] {
            let text = format!(
                "manifest_version = 2\n[[inject]]\nsource = 'init'\nlibrary = 'lib.so'\n[inject.filter]\n{fields}"
            );
            assert!(toml::from_str::<ManifestConfig>(&text).is_err());
        }
    }

    #[test]
    fn rejects_invalid_versions_libraries_and_static_fields() {
        for text in [
            "inject = []",
            "manifest_version = '2'",
            "manifest_version = 3\ninject = []",
            "manifest_version = 2\ninject = []",
            "manifest_version = 2\nunknown = true\ninject = []",
        ] {
            assert!(ModuleManifest::parse(text).is_err());
        }
        for library in ["../lib.so", "/lib.so", "", "."] {
            let text = format!(
                "manifest_version = 2\n[[inject]]\nsource = 'zygote'\nlibrary = '{library}'\n[inject.filter]\ntype = 'static'"
            );
            assert!(ModuleManifest::parse(&text).is_err());
        }
        for fields in [
            "packages = []",
            "packages = ['']",
            "process_name_matches = '['",
            "process_name = 'app'\nprocess_name_matches = 'app'",
            "uid = 12000",
            "uid = '1,,2'",
            "user_id = '9-1'",
        ] {
            assert!(rule("zygote", fields).is_err(), "accepted {fields}");
        }
    }
}
