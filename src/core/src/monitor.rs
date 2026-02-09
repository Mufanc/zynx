use anyhow::{Context, Result, anyhow};
use aya::maps::{Array, HashMap, Map, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, include_bytes_aligned};
use aya_log::EbpfLogger;
use log::{error, info, warn};
use nix::libc::RLIM_INFINITY;
use nix::sys::resource;
use nix::sys::resource::Resource;
use nix::unistd::Pid;
use parking_lot::Mutex;
use std::ffi::CStr;
use std::mem;
use std::sync::OnceLock;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task;
use zynx_ebpf_shared::Message as EbpfMessage;

static INSTANCE: OnceLock<Monitor> = OnceLock::new();

pub struct Config {
    pub target_paths: Vec<String>,
    pub target_names: Vec<String>,
}

pub struct Monitor {
    channel: AsyncMutex<AsyncFd<RingBuf<MapData>>>,
    zygote_info: Mutex<Array<MapData, i32>>,
    _ebpf: Ebpf,
}

#[derive(Debug)]
pub enum Message {
    PathMatches(Pid, String),
    NameMatches(Pid, String),
    ZygoteFork(Pid),
    ZygoteCrashed(Pid),
}

fn parse_string(data: &[u8]) -> String {
    let cstr = CStr::from_bytes_until_nul(data).expect("failed to parse string");
    cstr.to_string_lossy().to_string()
}

impl From<EbpfMessage> for Message {
    fn from(value: EbpfMessage) -> Self {
        match value {
            EbpfMessage::PathMatches(pid, path) => {
                Message::PathMatches(Pid::from_raw(pid), parse_string(&path))
            }
            EbpfMessage::NameMatches(pid, name) => {
                Message::NameMatches(Pid::from_raw(pid), parse_string(&name))
            }
            EbpfMessage::ZygoteFork(pid) => Message::ZygoteFork(Pid::from_raw(pid)),
            EbpfMessage::ZygoteCrashed(pid) => Message::ZygoteCrashed(Pid::from_raw(pid)),
        }
    }
}

fn take_map<T: TryFrom<Map>>(ebpf: &mut Ebpf, name: &str) -> Result<T>
where
    <T as TryFrom<Map>>::Error: Into<anyhow::Error>,
{
    ebpf.take_map(name)
        .context(format!("failed to take map: {name}"))
        .and_then(|map| map.try_into().map_err(Into::into))
}

impl Monitor {
    fn new(config: Config) -> Result<Self> {
        resource::setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY)?;

        let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/zynx-ebpf"
        )))?;

        match EbpfLogger::init(&mut ebpf) {
            Ok(logger) => {
                let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;

                task::spawn(async move {
                    loop {
                        let mut asyncfd = logger.readable_mut().await.unwrap();
                        asyncfd.get_inner_mut().flush();
                        asyncfd.clear_ready();
                    }
                });
            }
            Err(err) => {
                warn!("failed to initialize eBPF logger: {err:?}");
            }
        }

        let mut target_paths: HashMap<_, [u8; 128], u8> = take_map(&mut ebpf, "TARGET_PATHS")?;
        let mut target_names: HashMap<_, [u8; 16], u8> = take_map(&mut ebpf, "TARGET_NAMES")?;

        for path in &config.target_paths {
            let mut buffer = [0u8; 128];
            let len = path.len().min(buffer.len());

            buffer[..len].copy_from_slice(&path.as_bytes()[..len]);

            target_paths.insert(buffer, 0, 0)?;
        }

        for name in &config.target_names {
            let mut buffer = [0u8; 16];
            let len = name.len().min(buffer.len());

            buffer[..len].copy_from_slice(&name.as_bytes()[..len]);

            target_names.insert(buffer, 0, 0)?;
        }

        for (name, program) in ebpf.programs_mut() {
            let parts: Vec<_> = name.split("__").collect();

            if parts[0] == "tracepoint" {
                let program: &mut TracePoint = program.try_into()?;
                let (category, name) = (parts[1], parts[2]);

                info!("attaching tracepoint: {category}/{name}");

                program.load()?;
                program.attach(category, name)?;
            }
        }

        let channel =
            AsyncFd::with_interest(take_map(&mut ebpf, "MESSAGE_CHANNEL")?, Interest::READABLE)?;
        let zygote_info = take_map(&mut ebpf, "ZYGOTE_INFO")?;

        Ok(Self {
            channel: AsyncMutex::new(channel),
            zygote_info: Mutex::new(zygote_info),
            _ebpf: ebpf,
        })
    }

    pub async fn recv_msg(&self) -> Option<Message> {
        loop {
            let mut channel = self.channel.lock().await;
            let mut asyncfd = channel.readable_mut().await.ok()?;
            let entry = asyncfd.get_inner_mut().next();

            if entry.is_none() {
                drop(entry);
                asyncfd.clear_ready();
                continue;
            }

            let buffer: [u8; size_of::<EbpfMessage>()] = (*entry.unwrap())
                .try_into()
                .inspect_err(|err| error!("failed to parse channel message: {err:?}"))
                .ok()?;
            let message: EbpfMessage = unsafe { mem::transmute(buffer) };

            break Some(message.into());
        }
    }

    pub fn attach_zygote(&self, pid: i32) -> Result<()> {
        let mut zygote_info = self.zygote_info.lock();
        zygote_info.set(0, pid, 0 /* BPF_ANY */)?;
        Ok(())
    }

    pub fn init(config: Config) -> Result<()> {
        let monitor = Self::new(config)?;
        INSTANCE
            .set(monitor)
            .map_err(|_| anyhow!("Monitor already initialized"))?;
        Ok(())
    }

    pub fn instance() -> &'static Self {
        INSTANCE.get().expect("monitor is not running")
    }
}
