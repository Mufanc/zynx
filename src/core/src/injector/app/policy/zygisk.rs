use super::zynx::LoadedModule;
use super::{PolicyDecision, PolicyProvider, ProcessInfo};
use async_trait::async_trait;
use log::warn;
use std::sync::{Arc, OnceLock};
use zynx_bridge_shared::zygote::ProviderType;

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
    fn provider_type(&self) -> ProviderType {
        ProviderType::Zygisk
    }

    async fn check(&self, process: &ProcessInfo) -> PolicyDecision {
        let Some(modules) = self.modules.get() else {
            return PolicyDecision::Deny;
        };
        let mut attachments = Vec::new();

        for module in modules {
            match module.check_zygisk(process).await {
                Ok(Some(attachment)) => attachments.push(attachment),
                Ok(None) => {}
                Err(error) => warn!("Zygisk filter check failed: {error:#}"),
            }
        }

        if attachments.is_empty() {
            PolicyDecision::Deny
        } else {
            PolicyDecision::allow_with_attachments(attachments)
        }
    }
}
