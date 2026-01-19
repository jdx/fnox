//! Event handling for TUI
//!
//! Handles keyboard input, mouse input, and async events using tokio channels.

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, MouseEvent};
use tokio::sync::mpsc;

use crate::tui::app::Message;

/// Events that can occur in the TUI
#[derive(Debug)]
pub enum Event {
    /// Keyboard input event
    Key(KeyEvent),
    /// Mouse input event
    Mouse(MouseEvent),
    /// Periodic tick for UI updates
    Tick,
    /// Async message from background tasks
    Message(Message),
}

/// Handles event collection from multiple sources
pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    tx: mpsc::UnboundedSender<Event>,
}

impl EventHandler {
    /// Create a new event handler with the specified tick rate
    pub fn new(tick_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn keyboard event handler
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            loop {
                // Poll for events with tick rate as timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    if let Ok(evt) = event::read() {
                        match evt {
                            CrosstermEvent::Key(key) => {
                                if tx_clone.send(Event::Key(key)).is_err() {
                                    break;
                                }
                            }
                            CrosstermEvent::Mouse(mouse) => {
                                if tx_clone.send(Event::Mouse(mouse)).is_err() {
                                    break;
                                }
                            }
                            CrosstermEvent::Resize(_, _) => {
                                // Terminal resize - send tick to trigger redraw
                                if tx_clone.send(Event::Tick).is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    // Timeout - send tick
                    if tx_clone.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        });

        Self { rx, tx }
    }

    /// Get a sender for sending messages from async tasks
    pub fn message_tx(&self) -> mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }

    /// Wait for the next event
    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}
