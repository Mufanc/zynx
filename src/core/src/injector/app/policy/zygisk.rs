use anyhow::Result;
use crate::android::packages::PackageInfoService;
use crate::injector::app::policy::proto::{CheckArgsFast, CheckArgsSlow, PackageInfo};
use crate::injector::app::policy::{EmbryoCheckArgs, EmbryoCheckArgsFast, PolicyDecision, PolicyProvider};
use async_trait::async_trait;

struct ZygiskModule {

}

impl ZygiskModule {
    async fn check_fast(&self, _args: &CheckArgsFast) -> bool {
        false
    }

    async fn check_slow(&self, _args: &CheckArgsSlow) -> bool {
        false
    }
}

pub struct ZygiskPolicyProvider {
    modules: Vec<ZygiskModule>
}

#[async_trait]
impl PolicyProvider for ZygiskPolicyProvider {
    async fn init(&self) -> Result<()> {

        Ok(())
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        match args {
            EmbryoCheckArgs::Fast(fast) => {
                let args = build_fast_args(fast);

                // Todo: complete check logic

                for module in &self.modules {
                    module.check_fast(&args).await;
                }
            }
            EmbryoCheckArgs::Slow(slow) => {
                let args = CheckArgsSlow {
                    fast: Some(build_fast_args(&slow.fast_args)),  // Todo: make optional
                    nice_name: slow.nice_name.clone(),
                    app_data_dir: slow.app_data_dir.clone(),
                };

                for module in &self.modules {
                    module.check_slow(&args).await;
                }
            }
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
