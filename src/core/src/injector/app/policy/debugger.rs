use crate::injector::app::policy::{Action, PolicyDecision, PolicyProvider, ProcessInfo};
use async_trait::async_trait;
use zynx_bridge_shared::action::ActionData;
use zynx_misc::props::prop_on;

#[derive(Default)]
pub struct DebuggerPolicyProvider;

#[async_trait]
impl PolicyProvider for DebuggerPolicyProvider {
    async fn check(&self, args: &ProcessInfo) -> PolicyDecision {
        let Some(pkgs) = args.package_info.as_deref() else {
            return PolicyDecision::Deny;
        };

        let enable_debug = pkgs
            .iter()
            .any(|pkg| !pkg.debuggable && prop_on(&format!("debug.zynx.debuggable.{}", pkg.name)));

        if !enable_debug {
            return PolicyDecision::Deny;
        }

        match Action::new(None, ActionData::EnableDebugger) {
            Ok(action) => PolicyDecision::Allow(vec![action]),
            Err(_) => PolicyDecision::Deny,
        }
    }
}
