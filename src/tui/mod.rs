//! Terminal User Interface module for fnox
//!
//! Provides an interactive dashboard for managing secrets.

mod app;
mod event;
pub mod terminal;
pub mod ui;

pub mod components;

pub use app::App;
pub use event::{Event, EventHandler};
pub use terminal::{enter_terminal, leave_terminal};
