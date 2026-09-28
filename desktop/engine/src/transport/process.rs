//! Who runs the core an `Rpc` talks to: a child process of this application,
//! or (Windows TUN) the Thronium service, reached only through its pipe.
//!
//! The service keeps its worker to itself; closing the pipe is how this side
//! ends it, so for the service "exited" means only that this side let go.
use std::io;
use std::process::ExitStatus;
use tokio::process::Child;

// One per connection; boxing the child would buy nothing.
#[allow(clippy::large_enum_variant)]
pub(crate) enum CoreProcess {
    Local(Child),
    #[cfg(windows)]
    Service {
        released: bool,
    },
}

#[cfg(windows)]
fn released() -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

impl CoreProcess {
    pub(crate) fn id(&self) -> Option<u32> {
        match self {
            Self::Local(child) => child.id(),
            #[cfg(windows)]
            Self::Service { .. } => None,
        }
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Local(child) => child.try_wait(),
            #[cfg(windows)]
            Self::Service { released: done } => Ok(done.then(released)),
        }
    }
    pub(crate) async fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            Self::Local(child) => child.wait().await,
            #[cfg(windows)]
            Self::Service { released: done } => {
                *done = true;
                Ok(released())
            }
        }
    }
    pub(crate) async fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Local(child) => child.kill().await,
            #[cfg(windows)]
            Self::Service { released } => {
                *released = true;
                Ok(())
            }
        }
    }
    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        match self {
            Self::Local(child) => child.start_kill(),
            #[cfg(windows)]
            Self::Service { released } => {
                *released = true;
                Ok(())
            }
        }
    }
}
