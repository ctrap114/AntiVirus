use flume::{Receiver, Sender};
use notify::{Event, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher};
use parking_lot::Mutex;
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

const EVENT_CHANNEL_CAPACITY: usize = 4096;
const MAX_RETAINED_EVENTS: usize = 10_000;

#[pyclass]
pub struct FsMonitor {
    events: Arc<Mutex<Vec<String>>>,
    sender: Option<Sender<String>>,
    watcher: Option<RecommendedWatcher>,
    receiver: Option<Receiver<String>>,
}

#[pymethods]
impl FsMonitor {
    #[new]
    pub fn new() -> Self {
        FsMonitor {
            events: Arc::new(Mutex::new(Vec::new())),
            sender: None,
            watcher: None,
            receiver: None,
        }
    }

    pub fn watch_path(&mut self, path: &str) -> PyResult<()> {
        let path = PathBuf::from(path);
        // A filesystem storm must not grow an unbounded queue until it
        // exhausts the host process. Dropping newest events when the channel
        // is full is preferable to taking down the scanner.
        let (sender, receiver) = flume::bounded(EVENT_CHANNEL_CAPACITY);
        let events = self.events.clone();
        let sender_for_watcher = sender.clone();

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: NotifyResult<Event>| {
                if let Ok(event) = res {
                    let description = format!("{:?}: {:?}", event.kind, event.paths);
                    let _ = sender_for_watcher.try_send(description);
                }
            })
            .map_err(|err| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to create watcher: {}",
                    err
                ))
            })?;

        watcher
            .watch(&path, RecursiveMode::Recursive)
            .map_err(|err| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to watch path: {}",
                    err
                ))
            })?;

        let receiver_clone = receiver.clone();
        let events_clone = events.clone();
        thread::spawn(move || {
            while let Ok(message) = receiver_clone.recv() {
                let mut events = events_clone.lock();
                events.push(message);
                if events.len() > MAX_RETAINED_EVENTS {
                    let overflow = events.len() - MAX_RETAINED_EVENTS;
                    events.drain(..overflow);
                }
            }
        });

        self.sender = Some(sender);
        self.receiver = Some(receiver);
        self.watcher = Some(watcher);
        Ok(())
    }

    pub fn get_events<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyList>> {
        let events = self.events.lock();
        pyo3::types::PyList::new(py, events.clone())
    }

    pub fn clear_events(&self) {
        self.events.lock().clear();
    }
}
