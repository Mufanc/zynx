use crate::android::inotify::AsyncInotify;
use crate::android::packages::PackageInfoService;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::{Attachment, EmbryoCheckArgs, PolicyDecision, PolicyProvider};
use crate::misc::create_sealed_memfd;
use anyhow::{Result, bail};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use notify::EventKindMask;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex_lite::Regex;
use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{fmt, path::Path};
use tokio::{task, time};
use zynx_bridge_shared::policy::liteloader::{LibraryKind, LiteLoaderParams};
use zynx_bridge_shared::zygote::ProviderType;
use zynx_misc::selinux::FileExt;

static LITE_LIBRARIES_DIR: Lazy<PathBuf> = Lazy::new(|| "/data/adb/zynx/liteloader".into());
static LITE_LIBRARY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(.+)-(.+)\.(so|dex)$").unwrap());

type Libraries = HashMap<String, Vec<CachedLibraryEntry>>;
type LibrariesArcLocked = Arc<RwLock<Libraries>>;

#[derive(Clone)]
struct CachedLibraryEntry {
    mtime: SystemTime,
    path: PathBuf,
    fd: Arc<OwnedFd>,
    kind: LibraryKind,
}

impl Debug for CachedLibraryEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("CachedLibEntry")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

fn find_cached_entry<'a>(libs: &'a Libraries, path: &Path) -> Option<&'a CachedLibraryEntry> {
    libs.values().flatten().find(|entry| entry.path == path)
}

fn reload_libs(prev_libs: &Libraries) -> Result<Libraries> {
    let mut libs: Libraries = HashMap::new();
    let mut loaded = 0usize;
    let mut reused = 0usize;

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

        let current_mtime = match fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(err) => {
                warn!("failed to get mtime for {}: {err}", path.display());
                continue;
            }
        };

        let cached_entry = match find_cached_entry(prev_libs, &path) {
            Some(prev_entry) if prev_entry.mtime == current_mtime => {
                debug!("reusing cached: {}", path.display());
                reused += 1;
                prev_entry.clone()
            }
            _ => {
                info!("loading: {}", path.display());
                loaded += 1;

                let name = format!("liteloader::{library_name}");
                let fd = create_sealed_memfd(&name, &fs::read(&path)?)?;

                if env::var("MODDIR").is_ok() {
                    fd.as_file().mark_as_magisk_file();
                }

                let kind = match extension {
                    "so" => LibraryKind::Native,
                    "dex" => LibraryKind::Java,
                    _ => unreachable!(),
                };

                CachedLibraryEntry {
                    mtime: current_mtime,
                    path: path.clone(),
                    fd: Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd.into_raw_fd()) }),
                    kind,
                }
            }
        };

        libs.entry(package_name).or_default().push(cached_entry);
    }

    info!("reload complete: {loaded} loaded, {reused} reused");

    Ok(libs)
}

#[derive(Default)]
pub struct LiteLoaderPolicyProvider {
    libs: LibrariesArcLocked,
}

impl LiteLoaderPolicyProvider {
    fn reload_libs(libs: LibrariesArcLocked) {
        let prev_libs = libs.read().clone();

        match reload_libs(&prev_libs) {
            Ok(map) => {
                *libs.write() = map;
            }
            Err(err) => {
                warn!("failed to reload library list: {err:?}, keeping old data");
            }
        }
    }

    async fn watch_loop(mut inotify: AsyncInotify, libs: LibrariesArcLocked) -> Result<()> {
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
        if !ZynxConfigs::instance().enable_liteloader {
            return Ok(());
        }

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
        if !ZynxConfigs::instance().enable_liteloader {
            return PolicyDecision::Deny;
        }

        let libs = self.libs.read();
        let inject_libs = PackageInfoService::instance()
            .query(args.uid)
            .and_then(|pkgs| pkgs.iter().find_map(|pkg| libs.get(&pkg.name)));

        if let Some(libs) = inject_libs {
            let attachments: Vec<Attachment> = libs
                .iter()
                .map(|entry| {
                    let params = LiteLoaderParams {
                        lib_name: entry
                            .path
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        kind: entry.kind.clone(),
                    };
                    let data = wincode::serialize(&params).unwrap_or_default();

                    Attachment::with_both(entry.fd.clone(), data)
                })
                .collect();
            return PolicyDecision::allow_with_attachments(attachments);
        }

        PolicyDecision::Deny
    }
}
