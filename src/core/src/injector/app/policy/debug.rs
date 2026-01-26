use crate::injector::app::policy::{EmbryoCheckArgs, LibraryFile, PolicyDecision, PolicyProvider};
use anyhow::Result;
use log::debug;
use once_cell::sync::Lazy;
use std::sync::Arc;

static TEST_LIB: Lazy<Result<Arc<LibraryFile>>> =
    Lazy::new(|| LibraryFile::new("/data/local/tmp/libnothing.so").map(Arc::new));

pub struct SystemPolicyProvider;

impl PolicyProvider for SystemPolicyProvider {
    fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        let Ok(library) = &*TEST_LIB else {
            return PolicyDecision::Deny;
        };

        match args {
            EmbryoCheckArgs::Fast(fast) => {
                if let Some(info) = &fast.package_info {
                    debug!("package info: {:?}", info);
                }
                PolicyDecision::MoreInfo
            }
            EmbryoCheckArgs::Slow(slow) => {
                debug!("nice name = {:?}", slow.nice_name);

                if slow.is_system_server {
                    PolicyDecision::Allow(vec![library.clone()])
                } else {
                    PolicyDecision::Deny
                }
            }
        }
    }
}
