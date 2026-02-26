use crate::android::packages::PackageInfoService;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::{EmbryoCheckArgs, PolicyDecision, PolicyProvider};
use async_trait::async_trait;
use zynx_bridge_shared::policy::debugger::DebuggerParams;
use zynx_bridge_shared::zygote::ProviderType;
use zynx_misc::props::prop_on;

#[derive(Default)]
pub struct DebuggerPolicyProvider;

#[async_trait]
impl PolicyProvider for DebuggerPolicyProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Debugger
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        if !ZynxConfigs::instance().enable_debugger {
            return PolicyDecision::Deny;
        }

        let Some(pkgs) = PackageInfoService::instance().query(args.uid) else {
            return PolicyDecision::Deny;
        };

        let enable_debug = pkgs
            .iter()
            .any(|pkg| !pkg.debuggable && prop_on(&format!("debug.zynx.debuggable.{}", pkg.name)));

        if !enable_debug {
            return PolicyDecision::Deny;
        }

        let params = DebuggerParams {
            force_debuggable: true,
        };

        if let Ok(data) = wincode::serialize(&params) {
            PolicyDecision::allow_with_data(data)
        } else {
            PolicyDecision::Deny
        }
    }
}
