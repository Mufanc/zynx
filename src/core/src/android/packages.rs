use anyhow::Result;
use nix::unistd::{Gid, Uid};
use std::fs::File;
use std::io::{BufRead, BufReader};

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
