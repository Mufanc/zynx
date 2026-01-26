use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use anyhow::Result;
use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};
use nix::unistd::{Gid, Uid};
use once_cell::sync::Lazy;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

static PACKAGE_INFO_SERVICE: Lazy<PackageInfoService> =
    Lazy::new(|| PackageInfoService::new().expect("failed to init PackageInfoService"));

pub type PackageInfoLocked<'a> = MappedRwLockReadGuard<'a, [PackageInfo]>;

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
        .map(|s| s.parse().ok().map(|x| Gid::from_raw(x)))
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

pub fn parse_package_list() -> Result<Vec<PackageInfo>> {
    let file = File::open("/data/system/packages.list")?;
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
    fn new() -> Result<Self> {
        let packages = parse_package_list()?;
        let map = Self::build_map(packages);

        info!(
            "parsed {} packages from packages.list",
            map.values().map(|v| v.len()).sum::<usize>()
        );

        let inotify = Inotify::init()?;
        inotify.watches().add("/data/system", WatchMask::MOVED_TO)?;

        let data = Arc::new(RwLock::new(map));
        let watch_task = Self::spawn_watch_task(inotify, Arc::clone(&data));

        Ok(Self {
            data,
            _watch_task: watch_task,
        })
    }

    /// Trigger lazy initialization
    pub fn init() {
        Lazy::force(&PACKAGE_INFO_SERVICE);
    }

    pub fn instance() -> &'static Self {
        &PACKAGE_INFO_SERVICE
    }

    pub fn query(&self, uid: Uid) -> Option<PackageInfoLocked<'_>> {
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

    fn spawn_watch_task(
        inotify: Inotify,
        data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    ) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            if let Err(e) = Self::watch_loop(inotify, data).await {
                error!("inotify watch loop exited with error: {e:?}");
            }
        })
    }

    async fn watch_loop(
        mut inotify: Inotify,
        data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    ) -> Result<()> {
        let async_fd = AsyncFd::with_interest(inotify.as_raw_fd(), Interest::READABLE)?;

        let mut buffer = [0u8; 0x4000];

        loop {
            let mut lock = async_fd.readable().await?;

            let events = inotify.read_events(&mut buffer)?;
            for event in events {
                if event.name.is_some_and(|name| name == "packages.list") {
                    debug!("detected packages.list update, reloading...");
                    Self::reload_packages(&data);
                }
            }

            lock.clear_ready();
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

                info!("reloaded {} packages from packages.list", count);
            }
            Err(err) => {
                warn!("failed to reload packages.list: {err:?}, keeping old data");
            }
        }
    }
}
