//! Mock implementations for testing the collector module.

mod handler;
pub use handler::{Event as HandlerEvent, Handler as MockHandler};

mod monitor;
pub use monitor::{Event as MonitorEvent, Monitor as MockMonitor};

mod request;
pub use request::{Request, Response};

mod key;
pub use key::MockPublicKey;
