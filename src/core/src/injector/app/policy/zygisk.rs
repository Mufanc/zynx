use super::module::LoadedModule;
use super::{PolicyDecision, PolicyProvider, ProcessInfo};
use async_trait::async_trait;
use log::warn;
use std::sync::{Arc, OnceLock};

pub(super) struct ZygiskPolicyProvider {
    modules: Arc<OnceLock<Vec<LoadedModule>>>,
}

impl ZygiskPolicyProvider {
    pub(super) fn new(modules: Arc<OnceLock<Vec<LoadedModule>>>) -> Self {
        Self { modules }
    }
}

#[async_trait]
impl PolicyProvider for ZygiskPolicyProvider {
    async fn check(&self, process: &ProcessInfo) -> PolicyDecision {
        let Some(modules) = self.modules.get() else {
            return PolicyDecision::Deny;
        };
        let mut actions = Vec::new();

        for module in modules {
            match module.check_zygisk(process).await {
                Ok(Some(action)) => actions.push(action),
                Ok(None) => {}
                Err(error) => warn!("Zygisk filter check failed: {error:#}"),
            }
        }

        if actions.is_empty() {
            PolicyDecision::Deny
        } else {
            PolicyDecision::Allow(actions)
        }
    }
}
