use anyhow::Result;
use once_cell::sync::OnceCell;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::{Handle, Signals};
use tokio::sync::broadcast;

const SIGNAL_BUFFER: usize = 8;

struct SignalManager {
    handle: Handle,
    sender: broadcast::Sender<i32>,
}

impl SignalManager {
    fn new() -> Result<Self> {
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let handle = signals.handle();
        let (sender, _) = broadcast::channel(SIGNAL_BUFFER);
        let thread_sender = sender.clone();

        std::thread::spawn(move || {
            for signal in signals.forever() {
                let _ = thread_sender.send(signal);
            }
        });

        Ok(Self { handle, sender })
    }

    fn subscribe(&self) -> broadcast::Receiver<i32> {
        self.sender.subscribe()
    }

    fn rearm(&self) -> Result<()> {
        self.handle.add_signal(SIGINT)?;
        self.handle.add_signal(SIGTERM)?;
        Ok(())
    }
}

static SIGNAL_MANAGER: OnceCell<SignalManager> = OnceCell::new();

fn manager() -> Result<&'static SignalManager> {
    SIGNAL_MANAGER.get_or_try_init(SignalManager::new)
}

pub fn init() -> Result<()> {
    manager().map(|_| ())
}

pub fn subscribe() -> Result<broadcast::Receiver<i32>> {
    Ok(manager()?.subscribe())
}

pub fn rearm() -> Result<()> {
    manager()?.rearm()
}

pub fn signal_name(signal: i32) -> &'static str {
    match signal {
        SIGINT => "SIGINT",
        SIGTERM => "SIGTERM",
        _ => "UNKNOWN",
    }
}
