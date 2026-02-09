use crate::android::packages::PackageInfoService;
use crate::injector::app::policy::proto::{CheckArgsFast, CheckArgsSlow, PackageInfo};
use crate::injector::app::policy::{
    EmbryoCheckArgs, EmbryoCheckArgsFast, PolicyDecision, PolicyProvider,
};
use anyhow::Result;
use async_trait::async_trait;
use std::any::Any;

use zynx_bridge_types::zygote::ProviderType;

struct ZygiskModule {}

impl ZygiskModule {
    async fn check_fast(&self, _args: &CheckArgsFast) -> bool {
        false
    }

    async fn check_slow(&self, _args: &CheckArgsSlow) -> bool {
        false
    }
}

#[derive(Default)]
pub struct ZygiskPolicyProvider {
    modules: Vec<ZygiskModule>,
}

#[async_trait]
impl PolicyProvider for ZygiskPolicyProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Zygisk
    }

    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        let args = build_fast_args(args.assume_fast());

        // Todo: complete check logic

        for module in &self.modules {
            module.check_fast(&args).await;
        }

        PolicyDecision::MoreInfo(Some(Box::new(args)))
    }

    async fn recheck(
        &self,
        args: &EmbryoCheckArgs<'_>,
        state: Box<dyn Any + Send + Sync>,
    ) -> PolicyDecision {
        let slow = args.assume_slow();

        let fast_args = state
            .downcast::<CheckArgsFast>()
            .map(|b| *b)
            .expect("failed to downcast cached state");

        let args = CheckArgsSlow {
            fast: Some(fast_args), // Todo: it's optional
            nice_name: slow.nice_name.clone(),
            app_data_dir: slow.app_data_dir.clone(),
        };

        for module in &self.modules {
            module.check_slow(&args).await;
        }

        PolicyDecision::Deny
    }
}

fn build_fast_args(fast: &EmbryoCheckArgsFast) -> CheckArgsFast {
    let packages: Vec<_> = PackageInfoService::instance()
        .query(fast.uid)
        .map(|pkgs| {
            pkgs.iter()
                .map(|pkg| PackageInfo {
                    package_name: pkg.name.clone(),
                    debuggable: pkg.debuggable,
                    data_dir: pkg.data_dir.clone(),
                    seinfo: pkg.seinfo.clone(),
                    gids: vec![],
                })
                .collect()
        })
        .unwrap_or_default();

    CheckArgsFast {
        uid: fast.uid.as_raw(),
        gid: fast.gid.as_raw(),
        is_system_server: fast.is_system_server,
        is_child_zygote: fast.is_child_zygote,
        package_info: packages,
    }
}
