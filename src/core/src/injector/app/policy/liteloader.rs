use crate::android::inotify::AsyncInotify;
use crate::android::packages::PackageInfoService;
use crate::injector::app::policy::{
    EmbryoCheckArgs, InjectLibrary, PolicyDecision, PolicyProvider,
};
use anyhow::{Result, bail};
use async_trait::async_trait;
use log::{error, info, warn};
use notify::EventKindMask;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex_lite::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{task, time};
use zynx_bridge_shared::zygote::ProviderType;

static LITE_LIBRARIES_DIR: Lazy<PathBuf> = Lazy::new(|| "/data/adb/zynx/liteloader".into());
static LITE_LIBRARY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(.+)-(.+)\.(so|dex)$").unwrap());

type Libraries = HashMap<String, Vec<Arc<InjectLibrary>>>;
type LibrariesArcLocked = Arc<RwLock<Libraries>>;

fn reload_libs() -> Result<Libraries> {
    let mut libs: Libraries = HashMap::new();

    for entry in LITE_LIBRARIES_DIR.read_dir()?.flatten() {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };

        let (package_name, library_name, extension) = match LITE_LIBRARY_REGEX.captures(file_name) {
            Some(caps) => (
                caps.get(1).unwrap().as_str().to_string(),
                caps.get(2).unwrap().as_str().to_string(),
                caps.get(3).unwrap().as_str(),
            ),
            None => {
                warn!("skipping file with invalid name: {file_name}");
                continue;
            }
        };

        let name = format!("liteloader::{library_name}");
        let library = match extension {
            "so" => InjectLibrary::new(path, &name)?,
            "dex" => InjectLibrary::new_java(path, &name)?,
            _ => unreachable!(),
        };

        libs.entry(package_name)
            .or_default()
            .push(Arc::new(library));
    }

    info!("found libs: {libs:?}");

    Ok(libs)
}

#[derive(Default)]
pub struct LiteLoaderPolicyProvider {
    // a package name -> libraries map
    libs: LibrariesArcLocked,
}

impl LiteLoaderPolicyProvider {
    fn reload_libs(libs: LibrariesArcLocked) {
        match reload_libs() {
            Ok(map) => {
                let mut libs = libs.write();
                *libs = map;
                info!("reloaded {} libraries", libs.len());
            }
            Err(err) => {
                warn!("failed to reload library list: {err:?}, keeping old data");
            }
        }
    }

    async fn watch_loop(mut inotify: AsyncInotify, libs: LibrariesArcLocked) -> Result<()> {
        // Fixme: just reload changed file
        const DEBOUNCE: Duration = Duration::from_millis(200);

        loop {
            inotify.wait().await?;

            loop {
                tokio::select! {
                    result = inotify.wait() => {
                        result?;
                    }
                    _ = time::sleep(DEBOUNCE) => {
                        break;
                    }
                }
            }

            task::block_in_place(|| Self::reload_libs(libs.clone()))
        }
    }
}

#[async_trait]
impl PolicyProvider for LiteLoaderPolicyProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::LiteLoader
    }

    async fn init(&self) -> Result<()> {
        match fs::metadata(&*LITE_LIBRARIES_DIR) {
            Ok(meta) => {
                if !meta.is_dir() {
                    bail!(
                        "path `{}` exists but is not a directory",
                        LITE_LIBRARIES_DIR.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&*LITE_LIBRARIES_DIR)?;
            }
            Err(err) => return Err(err.into()),
        }

        task::block_in_place(|| Self::reload_libs(self.libs.clone()));

        let inotify = AsyncInotify::new(
            &*LITE_LIBRARIES_DIR,
            EventKindMask::CREATE
                | EventKindMask::MODIFY_NAME
                | EventKindMask::ACCESS_CLOSE
                | EventKindMask::REMOVE,
        )?;
        let libs = self.libs.clone();

        task::spawn(async move {
            if let Err(err) = Self::watch_loop(inotify, libs).await {
                error!("inotify watch loop exited with error: {err:?}")
            }
        });

        Ok(())
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        let libs = self.libs.read();
        let inject_libs = PackageInfoService::instance()
            .query(args.uid)
            .and_then(|pkgs| pkgs.iter().find_map(|pkg| libs.get(&pkg.name)));

        if let Some(libs) = inject_libs {
            return PolicyDecision::allow_with_libs(libs.clone());
        }

        PolicyDecision::Deny
    }
}
