use super::numeric_set::NumericSet;
use crate::android::PER_USER_RANGE;
use crate::injector::app::policy::ProcessInfo;
use crate::injector::app::policy::filter::ExternalFilter;
use regex_lite::Regex;
use std::path::PathBuf;

#[derive(Debug)]
pub(super) struct ModuleManifest {
    pub(super) rules: Vec<InjectionRule>,
    pub(super) zygisk: Option<ZygoteFilter>,
}

#[derive(Debug)]
pub(super) enum InjectionRule {
    Zygote {
        library: PathBuf,
        filter: ZygoteFilter,
    },
    Init {
        library: PathBuf,
        conditions: InitConditions,
    },
}

impl InjectionRule {
    pub(super) fn library(&self) -> &PathBuf {
        match self {
            Self::Zygote { library, .. } | Self::Init { library, .. } => library,
        }
    }
}

#[derive(Debug)]
pub(super) enum ZygoteFilter {
    Static(ZygoteConditions),
    External(ExternalFilter),
}

#[derive(Debug)]
pub(super) struct ZygoteConditions {
    pub(super) uid: Option<NumericSet>,
    pub(super) user_id: Option<NumericSet>,
    pub(super) packages: Option<Vec<String>>,
    pub(super) process_name: Option<String>,
    pub(super) process_name_matches: Option<Regex>,
    pub(super) is_system_server: Option<bool>,
    pub(super) is_child_zygote: Option<bool>,
}

#[derive(Debug)]
pub(super) struct InitConditions {
    pub(super) path: Option<PathBuf>,
    pub(super) name: Option<String>,
    pub(super) uid: Option<NumericSet>,
    pub(super) user_id: Option<NumericSet>,
}

impl ZygoteFilter {
    pub(super) async fn check(&self, process: &ProcessInfo) -> anyhow::Result<bool> {
        match self {
            Self::Static(conditions) => Ok(conditions.matches(process)),
            Self::External(filter) => filter.check(process).await,
        }
    }
}

macro_rules! matches_if_set {
    ($field:expr, $expected:ident => $check:expr) => {
        ($field).as_ref().is_none_or(|$expected| $check)
    };
}

impl ZygoteConditions {
    pub(super) fn matches(&self, args: &ProcessInfo) -> bool {
        let uid = args.uid.as_raw();

        matches_if_set!(self.uid, set => set.contains(uid))
            && matches_if_set!(self.user_id, set => set.contains(uid / PER_USER_RANGE))
            && matches_if_set!(self.is_system_server, value => *value == args.is_system_server)
            && matches_if_set!(self.is_child_zygote, value => *value == args.is_child_zygote)
            && matches_if_set!(self.packages, packages => {
                args.package_info.as_deref().is_some_and(|entries| {
                    entries.iter().any(|package| packages.contains(&package.name))
                })
            })
            && matches_if_set!(self.process_name, expected => {
                args.nice_name.as_ref().is_some_and(|name| name == expected)
            })
            && matches_if_set!(self.process_name_matches, regex => {
                args.nice_name.as_deref().is_some_and(|name| regex.is_match(name))
            })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn optional_checks_preserve_short_circuiting() {
        let absent: Option<bool> = None;
        assert!(matches_if_set!(absent, _value => panic!("absent condition was checked")));
        let reject = Some(false);
        let mut reached = false;
        let matched = matches_if_set!(reject, value => *value)
            && matches_if_set!(Some(true), value => {
                reached = true;
                *value
            });
        assert!(!matched);
        assert!(!reached);
    }
}
