use anyhow::{Context, Result};
use notify::{Config, Event, EventKindMask, INotifyWatcher, RecursiveMode, Watcher};
use std::path::Path;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use zynx_utils::ext::ResultExt;

pub struct AsyncInotify {
    rx: Receiver<Result<Event>>,
    _watcher: INotifyWatcher,
}

impl AsyncInotify {
    pub fn new<P: AsRef<Path>>(path: P, mask: EventKindMask) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1);
        let mut watcher = INotifyWatcher::new(
            move |res: notify::Result<Event>| {
                tx.blocking_send(res.map_err(|err| err.into()))
                    .log_if_error();
            },
            Config::default().with_event_kinds(mask),
        )?;

        watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

        Ok(Self {
            rx,
            _watcher: watcher,
        })
    }

    pub async fn wait(&mut self) -> Result<Event> {
        self.rx.recv().await.context("channel closed")?
    }
}
