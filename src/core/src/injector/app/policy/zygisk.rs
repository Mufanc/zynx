use crate::android::packages::PackageInfoService;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::proto::{CheckArgsFast, CheckArgsSlow, CheckResult, PackageInfo};
use crate::injector::app::policy::{
    EmbryoCheckArgs, EmbryoCheckArgsFast, PolicyDecision, PolicyProvider,
};
use anyhow::Result;
use async_trait::async_trait;
use log::{info, warn};
use parking_lot::RwLock;
use serde::Deserialize;
use std::any::Any;
use std::fs;
use std::path::{Path, PathBuf};
use zynx_bridge_shared::zygote::ProviderType;

const MODULES_DIR: &str = "/data/adb/modules";

#[derive(Debug, Deserialize)]
struct ZygiskModuleConfig {
    filter: FilterConfig,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FilterConfig {
    Stdio {
        path: PathBuf,
        #[serde(default)]
        args: Vec<String>,
    },
    SocketFile {
        path: PathBuf,
    },
}

enum FilterType {
    Stdio(PathBuf, Vec<Box<str>>),
    SocketFile(PathBuf),
}

struct ZygiskAdapter {
    module_id: String,
    filter: FilterType,
}

impl ZygiskAdapter {
    fn check_fast(&self, _args: &CheckArgsFast) -> bool {
        false
    }

    fn check_slow(&self, args: &CheckArgsSlow) -> bool {
        match &self.filter {
            FilterType::Stdio(path, _expected_args) => {
                if let Some(nice_name) = &args.nice_name {
                    path.to_str().is_some_and(|p| nice_name.contains(p))
                } else {
                    false
                }
            }
            FilterType::SocketFile(socket_path) => {
                socket_path.exists()
            }
        }
    }
}

fn scan_modules() -> Result<Vec<ZygiskAdapter>> {
    let modules_dir = Path::new(MODULES_DIR);
    if !modules_dir.exists() {
        return Ok(Vec::new());
    }

    let mut adapters = Vec::new();

    for entry in modules_dir.read_dir()?.flatten() {
        let module_dir = entry.path();
        if !module_dir.is_dir() {
            continue;
        }

        let module_id = match module_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
        {
            Some(id) => id,
            None => continue,
        };

        if module_dir.join("disable").exists() {
            info!("skipping disabled module: {module_id}");
            continue;
        }

        let config_path = module_dir.join("zynx-configs.toml");
        if !config_path.exists() {
            continue;
        }

        let config_content = match fs::read_to_string(&config_path) {
            Ok(content) => content,
            Err(err) => {
                warn!("failed to read config for {module_id}: {err}");
                continue;
            }
        };

        let config: ZygiskModuleConfig = match toml::from_str(&config_content) {
            Ok(cfg) => cfg,
            Err(err) => {
                warn!("failed to parse config for {module_id}: {err}");
                continue;
            }
        };

        let filter = match config.filter {
            FilterConfig::Stdio { path, args } => {
                FilterType::Stdio(path, args.into_iter().map(|s| s.into()).collect())
            }
            FilterConfig::SocketFile { path } => FilterType::SocketFile(path),
        };

        info!("loaded module: {module_id}");
        adapters.push(ZygiskAdapter { module_id, filter });
    }

    info!("scan complete: {} modules loaded", adapters.len());
    Ok(adapters)
}

#[derive(Default)]
pub struct ZygiskPolicyProvider {
    adapters: RwLock<Vec<ZygiskAdapter>>,
}

#[async_trait]
impl PolicyProvider for ZygiskPolicyProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Zygisk
    }

    async fn init(&self) -> Result<()> {
        if !ZynxConfigs::instance().enable_zygisk {
            return Ok(());
        }

        let adapters = scan_modules()?;
        *self.adapters.write() = adapters;

        Ok(())
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        if !ZynxConfigs::instance().enable_zygisk {
            return PolicyDecision::Deny;
        }

        let args = build_fast_args(args.assume_fast());

        for module in self.adapters.read().iter() {
            module.check_fast(&args);
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
            fast: Some(fast_args),
            nice_name: slow.nice_name.clone(),
            app_data_dir: slow.app_data_dir.clone(),
        };

        for module in self.adapters.read().iter() {
            module.check_slow(&args);
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
