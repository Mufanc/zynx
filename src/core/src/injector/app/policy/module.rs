use crate::injector::app::policy::{Action, PolicyDecision, PolicyProvider, ProcessInfo};
use crate::misc;
use anyhow::Context;
use async_trait::async_trait;
use log::{info, warn};
use rustix::fs::{Mode, OFlags};
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use zynx_bridge_shared::action::ActionData;

mod manifest;
mod numeric_set;
mod rule;

use rule::{InjectionRule, ModuleManifest};

const MANIFEST_FILE: &str = "zynx.toml";

pub(super) struct LoadedModule {
    manifest: ModuleManifest,
    libraries: HashMap<PathBuf, Arc<OwnedFd>>,
    data: Vec<u8>,
    #[cfg(feature = "zygisk")]
    zygisk_action: Option<Action>,
}

#[derive(Default)]
pub(super) struct ModulePolicyProvider {
    modules: Arc<OnceLock<Vec<LoadedModule>>>,
    zygisk_enabled: bool,
}

impl LoadedModule {
    fn load(module_id: &str, module_dir: &Path, zygisk_enabled: bool) -> anyhow::Result<Self> {
        let module_dir = rustix::fs::open(
            module_dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut manifest_text = String::new();

        misc::open_file_beneath(&module_dir, Path::new(MANIFEST_FILE))?
            .read_to_string(&mut manifest_text)?;

        let manifest = ModuleManifest::parse(&manifest_text).context("invalid manifest")?;
        let mut libraries = HashMap::new();

        for rule in &manifest.rules {
            if matches!(rule, InjectionRule::Init { .. }) {
                warn!(
                    "module {module_id}: init injection is not implemented, skipping {}",
                    rule.library().display()
                );
                continue;
            }

            if libraries.contains_key(rule.library()) {
                continue;
            }

            let mut library = Vec::new();

            misc::open_file_beneath(&module_dir, rule.library())?
                .read_to_end(&mut library)
                .with_context(|| format!("failed to read library: {}", rule.library().display()))?;

            let name = format!("zynx::{module_id}");
            let fd = misc::create_sealed_memfd(&name, &library)?;

            libraries.insert(rule.library().clone(), Arc::new(fd));
        }

        #[cfg(feature = "zygisk")]
        let zygisk_action = if zygisk_enabled && manifest.zygisk.is_some() {
            let mut library = Vec::new();

            misc::open_file_beneath(&module_dir, Path::new("zygisk/arm64-v8a.so"))?
                .read_to_end(&mut library)?;

            let fd = misc::create_sealed_memfd(&format!("zynx::{module_id}::zygisk"), &library)?;
            Some(Action::new(
                Some(Arc::new(fd)),
                ActionData::LoadZygisk {
                    name: module_id.to_string(),
                },
            )?)
        } else {
            None
        };
        #[cfg(not(feature = "zygisk"))]
        let _ = zygisk_enabled;

        let data = wincode::serialize(&ActionData::LoadNative {
            name: module_id.to_string(),
        })?;

        Ok(Self {
            manifest,
            libraries,
            data,
            #[cfg(feature = "zygisk")]
            zygisk_action,
        })
    }

    #[cfg(feature = "zygisk")]
    pub(super) async fn check_zygisk(
        &self,
        process: &ProcessInfo,
    ) -> anyhow::Result<Option<Action>> {
        let (Some(filter), Some(action)) = (&self.manifest.zygisk, &self.zygisk_action) else {
            return Ok(None);
        };

        Ok(filter.check(process).await?.then(|| action.clone()))
    }
}

#[async_trait]
impl PolicyProvider for ModulePolicyProvider {
    async fn init(&self) -> anyhow::Result<()> {
        let Some(module_dir) = env::var_os("MODDIR") else {
            info!("MODDIR is not set, skip module scan");
            return Ok(());
        };

        let modules_dir = Path::new(&module_dir)
            .parent()
            .context("MODDIR has no parent directory")?;
        let modules = Self::scan_modules(modules_dir, self.zygisk_enabled)?;

        if self.modules.set(modules).is_err() {
            anyhow::bail!("ModulePolicyProvider is already initialized");
        }

        Ok(())
    }

    async fn check(&self, args: &ProcessInfo) -> PolicyDecision {
        let Some(modules) = self.modules.get() else {
            return PolicyDecision::Deny;
        };
        let mut actions = Vec::new();

        for module in modules {
            let mut matched = HashSet::new();

            for rule in &module.manifest.rules {
                let InjectionRule::Zygote { library, filter } = rule else {
                    continue;
                };

                if matched.contains(library) {
                    continue;
                }

                let allowed = match filter.check(args).await {
                    Ok(allowed) => allowed,
                    Err(error) => {
                        warn!(
                            "native library {}: filter check failed: {error:#}",
                            library.display()
                        );
                        false
                    }
                };

                if !allowed {
                    continue;
                }

                matched.insert(library);
                actions.push(Action {
                    fd: Some(module.libraries[library].clone()),
                    data: module.data.clone(),
                });
            }
        }

        if actions.is_empty() {
            PolicyDecision::Deny
        } else {
            PolicyDecision::Allow(actions)
        }
    }
}

impl ModulePolicyProvider {
    pub(super) fn new(zygisk_enabled: bool) -> Self {
        Self {
            zygisk_enabled,
            ..Self::default()
        }
    }

    #[cfg(feature = "zygisk")]
    pub(super) fn zygisk_provider(&self) -> super::zygisk::ZygiskPolicyProvider {
        super::zygisk::ZygiskPolicyProvider::new(self.modules.clone())
    }

    fn scan_modules(modules_dir: &Path, zygisk_enabled: bool) -> anyhow::Result<Vec<LoadedModule>> {
        if !modules_dir.exists() {
            return Ok(Vec::new());
        }

        let mut modules = Vec::new();

        for entry in modules_dir.read_dir()?.flatten() {
            let module_dir = entry.path();

            if !module_dir.is_dir() || module_dir.join("disable").exists() {
                continue;
            }

            let Some(module_id) = module_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if !module_dir.join(MANIFEST_FILE).exists() {
                continue;
            }

            match LoadedModule::load(module_id, &module_dir, zygisk_enabled) {
                Ok(module) => {
                    info!("loaded module: {module_id}");
                    modules.push(module);
                }
                Err(error) => warn!("failed to load module {module_id}: {error:#}"),
            }
        }

        info!("module scan complete: {} loaded", modules.len());
        Ok(modules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{Gid, Uid};
    use std::fs::File;

    #[cfg(target_os = "android")]
    #[test]
    fn loads_unique_library_files_and_rejects_missing_library() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            env::temp_dir().join(format!("zynx-module-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        scopeguard::defer! { std::fs::remove_dir_all(&directory).unwrap(); }
        std::fs::write(directory.join("first.so"), b"first library").unwrap();
        std::fs::write(directory.join("second.so"), b"second library").unwrap();
        let manifest = r#"
            manifest_version = 2

            [zygisk.filter]
            type = "static"
            uid = "10000-"

            [[inject]]
            source = "zygote"
            library = "first.so"

            [inject.filter]
            type = "static"
            process_name = "com.example"

            [[inject]]
            source = "zygote"
            library = "./first.so"

            [inject.filter]
            type = "static"
            process_name = "com.example"

            [[inject]]
            source = "zygote"
            library = "second.so"

            [inject.filter]
            type = "static"
            process_name = "com.example"

            [[inject]]
            source = "init"
            library = "service.so"

            [inject.filter]
            type = "static"
            path = "/vendor/bin/example-service"
        "#;
        std::fs::write(directory.join(MANIFEST_FILE), manifest).unwrap();
        let module = LoadedModule::load("test", &directory, false).unwrap();
        assert_eq!(module.libraries.len(), 2);
        assert_eq!(module.manifest.rules.len(), 4);
        std::fs::remove_file(directory.join("second.so")).unwrap();
        assert!(LoadedModule::load("test", &directory, false).is_err());
    }

    #[cfg(feature = "zygisk")]
    #[tokio::test]
    async fn loads_standard_zygisk_library_and_shares_modules_between_providers() {
        use super::super::proto::{CheckRequest, CheckResponse};
        use prost::Message;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let directory = std::env::temp_dir().join(format!("zynx-zygisk-{}", std::process::id()));
        std::fs::create_dir_all(directory.join("zygisk")).unwrap();
        scopeguard::defer! { std::fs::remove_dir_all(&directory).unwrap(); }
        let path = directory.join("filter.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            for allow in [false, true] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32_le().await.unwrap();
                let mut payload = vec![0; length as usize];
                stream.read_exact(&mut payload).await.unwrap();
                let request = CheckRequest::decode(payload.as_slice()).unwrap();
                assert_eq!(request.process.unwrap().uid, 10123);
                let response = CheckResponse {
                    protocol_version: request.protocol_version,
                    allow: Some(allow),
                }
                .encode_to_vec();
                stream.write_u32_le(response.len() as u32).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        std::fs::write(directory.join("native.so"), b"native").unwrap();
        std::fs::write(
            directory.join(MANIFEST_FILE),
            format!(
                r#"
            manifest_version = 2

            [zygisk.filter]
            type = "socket_file"
            path = "{}"

            [[inject]]
            source = "zygote"
            library = "native.so"

            [inject.filter]
            type = "static"
            process_name = "com.example"
        "#,
                path.display()
            ),
        )
        .unwrap();
        let disabled = LoadedModule::load("example", &directory, false).unwrap();
        assert!(disabled.zygisk_action.is_none());
        assert_eq!(disabled.libraries.len(), 1);
        assert!(LoadedModule::load("example", &directory, true).is_err());
        std::fs::write(directory.join("zygisk/arm64-v8a.so"), b"zygisk").unwrap();
        let module = LoadedModule::load("example", &directory, true).unwrap();
        let provider = ModulePolicyProvider::new(true);
        assert!(provider.modules.set(vec![module]).is_ok());
        let zygisk = provider.zygisk_provider();
        // Both providers must keep using the startup snapshot.
        std::fs::write(directory.join(MANIFEST_FILE), "invalid configuration").unwrap();
        assert!(matches!(
            zygisk.check(&args(10123)).await,
            PolicyDecision::Deny
        ));
        let PolicyDecision::Allow(actions) = zygisk.check(&args(10123)).await else {
            panic!("expected Zygisk action");
        };
        assert_eq!(actions.len(), 1);
        assert!(actions[0].fd.is_some());
        let data: ActionData = wincode::deserialize(&actions[0].data).unwrap();
        assert!(matches!(data, ActionData::LoadZygisk { name } if name == "example"));
        assert!(matches!(
            provider.check(&args(10123)).await,
            PolicyDecision::Allow(_)
        ));
        server.await.unwrap();
    }

    fn provider(input: &str) -> ModulePolicyProvider {
        let manifest = ModuleManifest::parse(input).unwrap();
        let libraries = manifest
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.library().clone(),
                    Arc::new(File::open("/dev/null").unwrap().into()),
                )
            })
            .collect();
        let provider = ModulePolicyProvider::default();
        assert!(
            provider
                .modules
                .set(vec![LoadedModule {
                    manifest,
                    libraries,
                    #[cfg(feature = "zygisk")]
                    zygisk_action: None,
                    data: wincode::serialize(&ActionData::LoadNative {
                        name: "example".into()
                    })
                    .unwrap(),
                }])
                .is_ok()
        );
        provider
    }

    fn args(uid: u32) -> ProcessInfo {
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

    #[tokio::test]
    async fn arbitrates_native_rules_and_allows_an_independent_fallback() {
        use crate::injector::app::policy::proto::{CheckRequest, CheckResponse};
        use prost::Message;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let path = std::env::temp_dir().join(format!("zynx-native-filter-{}", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        scopeguard::defer! { std::fs::remove_file(&path).unwrap(); }
        let server = tokio::spawn(async move {
            for allow in [false, true] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32_le().await.unwrap();
                let mut payload = vec![0; length as usize];
                stream.read_exact(&mut payload).await.unwrap();
                let request = CheckRequest::decode(payload.as_slice()).unwrap();
                let process = request.process.unwrap();
                assert_eq!(process.uid, 10123);
                assert_eq!(process.nice_name.as_deref(), Some("com.example"));
                let response = CheckResponse {
                    protocol_version: request.protocol_version,
                    allow: Some(allow),
                }
                .encode_to_vec();
                stream.write_u32_le(response.len() as u32).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        let provider = provider(&format!(
            r#"
            manifest_version = 2

            [[inject]]
            source = "zygote"
            library = "denied.so"

            [inject.filter]
            type = "socket_file"
            path = "{socket}"

            [[inject]]
            source = "zygote"
            library = "allowed.so"

            [inject.filter]
            type = "socket_file"
            path = "{socket}"

            [[inject]]
            source = "zygote"
            library = "allowed.so"

            [inject.filter]
            type = "socket_file"
            path = "{socket}"

            [[inject]]
            source = "zygote"
            library = "failed.so"

            [inject.filter]
            type = "socket_file"
            path = "{socket}.missing"

            [[inject]]
            source = "zygote"
            library = "denied.so"

            [inject.filter]
            type = "static"
            uid = "10123"
        "#,
            socket = path.display()
        ));
        let PolicyDecision::Allow(actions) = provider.check(&args(10123)).await else {
            panic!("expected matching libraries");
        };
        server.await.unwrap();
        assert_eq!(actions.len(), 2);
        let module = &provider.modules.get().unwrap()[0];
        for (action, path) in actions.iter().zip(["allowed.so", "denied.so"]) {
            assert!(Arc::ptr_eq(
                action.fd.as_ref().unwrap(),
                &module.libraries[Path::new(path)]
            ));
        }
    }

    #[tokio::test]
    async fn selects_multiple_libraries_once_in_matching_rule_order() {
        let provider = provider(
            r#"
            manifest_version = 2

            [[inject]]
            source = "zygote"
            library = "first.so"

            [inject.filter]
            type = "static"
            uid = "10123,110000-119999"
            user_id = "0"
            process_name = "com.example"

            [[inject]]
            source = "zygote"
            library = "other.so"

            [inject.filter]
            type = "static"
            process_name = "com.other"

            [[inject]]
            source = "zygote"
            library = "second.so"

            [inject.filter]
            type = "static"
            process_name_matches = '^com\.example$'

            [[inject]]
            source = "zygote"
            library = "./first.so"

            [inject.filter]
            type = "static"
            uid = "10123"
        "#,
        );
        let PolicyDecision::Allow(actions) = provider.check(&args(10123)).await else {
            panic!("expected matching libraries");
        };
        assert_eq!(actions.len(), 2);
        let module = &provider.modules.get().unwrap()[0];
        for (action, path) in actions.iter().zip(["first.so", "second.so"]) {
            assert!(Arc::ptr_eq(
                action.fd.as_ref().unwrap(),
                &module.libraries[Path::new(path)]
            ));
            let data: ActionData = wincode::deserialize(&action.data).unwrap();
            assert!(matches!(data, ActionData::LoadNative { name } if name == "example"));
        }
    }
}
