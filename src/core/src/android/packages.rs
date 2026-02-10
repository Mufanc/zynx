use crate::android::inotify::AsyncInotify;
use anyhow::{Result, anyhow};
use log::{debug, error, info, warn};
use nix::unistd::{Gid, Uid};
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, EventKindMask};
use once_cell::sync::Lazy;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::task;
use tokio::task::JoinHandle;

static PACKAGE_LIST_FILE: Lazy<PathBuf> = Lazy::new(|| "/data/system/packages.list".into());
static PACKAGE_INFO_SERVICE: OnceLock<PackageInfoService> = OnceLock::new();

pub type PackageInfoListLocked<'a> = MappedRwLockReadGuard<'a, [PackageInfo]>;

#[derive(Clone, Debug)]
pub struct PackageInfo {
    pub name: String,
    pub uid: Uid,
    pub debuggable: bool,
    pub data_dir: String,
    pub seinfo: String,
    pub gids: Vec<Gid>,
}

fn parse_gids(gids_str: &str) -> Option<Vec<Gid>> {
    if gids_str.is_empty() || gids_str == "none" {
        return Some(Vec::new());
    }

    gids_str
        .split(",")
        .map(|s| s.parse().ok().map(Gid::from_raw))
        .collect()
}

fn parse_line(line: &str) -> Option<PackageInfo> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();

    if fields.len() < 6 {
        return None;
    }

    let name = fields[0].into();
    let uid = Uid::from_raw(fields[1].parse().ok()?);
    let debuggable = fields[2] != "0";
    let data_dir = fields[3].into();
    let seinfo = fields[4].into();
    let gids = parse_gids(fields[5])?;

    Some(PackageInfo {
        name,
        uid,
        debuggable,
        data_dir,
        seinfo,
        gids,
    })
}

// Todo: async-fs
pub fn parse_package_list() -> Result<Vec<PackageInfo>> {
    let file = File::open(&*PACKAGE_LIST_FILE)?;
    let reader = BufReader::new(file);

    let packages: Vec<PackageInfo> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.is_empty())
        .filter_map(|line| parse_line(&line))
        .collect();

    Ok(packages)
}

pub struct PackageInfoService {
    data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    _watch_task: JoinHandle<()>,
}

impl PackageInfoService {
    pub fn init() -> Result<()> {
        let packages = task::block_in_place(parse_package_list)?;
        let map = Self::build_map(packages);

        info!(
            "parsed {} packages from packages.list",
            map.values().map(|v| v.len()).sum::<usize>()
        );

        let inotify = AsyncInotify::new(
            "/data/system",
            EventKindMask::CREATE | EventKindMask::MODIFY_NAME,
        )?;
        let data = Arc::new(RwLock::new(map));
        let data_clone = data.clone();

        let watch_task = task::spawn(async move {
            if let Err(err) = Self::watch_loop(inotify, data_clone).await {
                error!("inotify watch loop exited with error: {err:?}");
            }
        });

        PACKAGE_INFO_SERVICE
            .set(Self {
                data,
                _watch_task: watch_task,
            })
            .map_err(|_| anyhow!("duplicate called"))?;

        Ok(())
    }

    pub fn instance() -> &'static Self {
        PACKAGE_INFO_SERVICE
            .get()
            .expect("package info service not initialized")
    }

    pub fn query(&self, uid: Uid) -> Option<PackageInfoListLocked<'_>> {
        let lock = self.data.read();
        RwLockReadGuard::try_map(lock, |map| map.get(&uid).map(|v| v.as_slice())).ok()
    }

    fn build_map(packages: Vec<PackageInfo>) -> HashMap<Uid, Vec<PackageInfo>> {
        let mut map: HashMap<Uid, Vec<PackageInfo>> = HashMap::new();
        for info in packages {
            map.entry(info.uid).or_default().push(info);
        }
        map
    }

    async fn watch_loop(
        mut inotify: AsyncInotify,
        data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    ) -> Result<()> {
        loop {
            let event = inotify.wait().await?;

            if event.kind == EventKind::Modify(ModifyKind::Name(RenameMode::To))
                && event.paths.contains(&PACKAGE_LIST_FILE)
            {
                debug!("detected packages.list update, reloading...");
                task::block_in_place(|| Self::reload_packages(&data));
            }
        }
    }

    fn reload_packages(data: &RwLock<HashMap<Uid, Vec<PackageInfo>>>) {
        match parse_package_list() {
            Ok(packages) => {
                let new_map = Self::build_map(packages);
                let count: usize = new_map.values().map(|v| v.len()).sum();

                let mut data = data.write();
                *data = new_map;
                drop(data);

                info!("reloaded {count} packages from packages.list");
            }
            Err(err) => {
                warn!("failed to reload packages.list: {err:?}, keeping old data");
            }
        }
    }
}
