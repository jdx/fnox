//! TUI command - Interactive secrets dashboard

use std::time::Duration;

use clap::Args;

use crate::commands::Cli;
use crate::config::Config;
use crate::error::Result;
use crate::tui::terminal::install_panic_hook;
use crate::tui::ui;
use crate::tui::{App, Event, EventHandler, enter_terminal, leave_terminal};

/// Guard that ensures terminal is restored when dropped
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort terminal restoration on drop
        let _ = leave_terminal();
    }
}

#[derive(Debug, Args)]
pub struct TuiCommand;

impl TuiCommand {
    pub async fn run(&self, cli: &Cli, config: Config) -> Result<()> {
        let profile = Config::get_profile(cli.profile.as_deref());

        // Install panic hook to restore terminal on panic
        install_panic_hook();

        // Initialize terminal
        let mut terminal = enter_terminal().map_err(|e| {
            crate::error::FnoxError::Config(format!("Failed to initialize terminal: {}", e))
        })?;

        // Create guard to ensure terminal cleanup on any exit (error or success)
        let _guard = TerminalGuard;

        // Create app state
        let mut app = App::new(config, profile)?;

        // Create event handler
        let mut events = EventHandler::new(Duration::from_millis(250));

        // Store event tx for refresh operations
        app.set_event_tx(events.message_tx());

        // Spawn initial secret resolution
        app.spawn_resolve_secrets(events.message_tx());

        // Main event loop
        while app.running {
            // Render
            terminal
                .draw(|frame| ui::render(&mut app, frame))
                .map_err(|e| crate::error::FnoxError::Config(format!("Failed to render: {}", e)))?;

            // Handle events
            if let Some(event) = events.next().await {
                match event {
                    Event::Key(key) => app.handle_key(key),
                    Event::Mouse(mouse) => app.handle_mouse(mouse),
                    Event::Tick => {
                        // Periodic tick - could be used for animations/updates
                    }
                    Event::Message(msg) => app.handle_message(msg),
                }
            }
        }

        // Guard will restore terminal when dropped
        Ok(())
    }
}
