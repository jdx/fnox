//! Application state and message handling

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use indexmap::IndexMap;
use ratatui::layout::Rect;
use tokio::sync::mpsc;

use crate::config::{Config, SecretConfig};
use crate::error::Result;
use crate::secret_resolver::resolve_secrets_batch;
use crate::tui::event::Event;

/// Focus area in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Providers,
    Secrets,
}

/// Popup/modal state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Popup {
    None,
    Help,
    ProfilePicker,
    SecretDetail(String),  // Secret key being viewed
    ConfirmDelete(String), // Secret key to delete
    EditSecret(EditState), // Edit secret value
    SetSecret(SetState),   // Set new secret value
}

/// State for editing a secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    pub key: String,
    pub value: String,
    pub cursor: usize,
}

/// State for setting a new secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetState {
    pub key: String,
    pub value: String,
    pub field: SetField, // Which field is being edited
    pub cursor: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetField {
    Key,
    Value,
}

/// Messages that can be sent to the app
#[derive(Debug)]
pub enum Message {
    /// Secrets have been resolved (includes resolution_id to handle race conditions)
    SecretsResolved {
        resolution_id: u64,
        resolved: IndexMap<String, Option<String>>,
    },
    /// Error occurred (includes resolution_id to handle race conditions)
    Error { resolution_id: u64, message: String },
}

/// Main application state
pub struct App {
    /// Whether the app is running
    pub running: bool,

    /// Current focus area
    pub focus: Focus,

    /// Current popup state
    pub popup: Popup,

    /// Loaded config
    pub config: Config,

    /// Current profile name
    pub profile: String,

    /// Available profiles
    pub available_profiles: Vec<String>,

    /// Selected profile index in picker
    pub profile_picker_index: usize,

    /// Available providers
    pub providers: Vec<String>,

    /// Selected provider index
    pub provider_index: usize,

    /// Secrets from config
    pub secrets: IndexMap<String, SecretConfig>,

    /// Selected secret index
    pub secret_index: usize,

    /// Resolved secret values (key -> value)
    pub resolved_values: IndexMap<String, Option<String>>,

    /// Set of secrets currently being loaded
    pub loading_secrets: HashSet<String>,

    /// Whether initial load is in progress
    pub initial_loading: bool,

    /// Current resolution ID (incremented on each resolution to handle race conditions)
    pub current_resolution_id: u64,

    /// Current error message to display
    pub error_message: Option<String>,

    /// Temporary status message (e.g., "Copied!")
    pub status_message: Option<String>,

    /// Search filter string
    pub search_filter: String,

    /// Whether we're in search mode
    pub searching: bool,

    /// Whether to show secret values in the list (instead of ******)
    pub show_values: bool,

    /// Channel sender for async operations
    pub event_tx: Option<mpsc::UnboundedSender<Event>>,

    /// Layout areas for mouse click detection
    pub providers_area: Rect,
    pub secrets_area: Rect,

    /// Scroll offsets for mouse click handling (updated during render)
    pub providers_scroll_offset: usize,
    pub secrets_scroll_offset: usize,
}

impl App {
    /// Create a new app with the given config and profile
    pub fn new(config: Config, profile: String) -> Result<Self> {
        let providers: Vec<String> = config.get_providers(&profile).keys().cloned().collect();
        let secrets = config.get_secrets(&profile)?;

        // Build list of available profiles
        let mut available_profiles = vec!["default".to_string()];
        available_profiles.extend(config.profiles.keys().cloned());
        available_profiles.sort();
        available_profiles.dedup();

        Ok(Self {
            running: true,
            focus: Focus::Secrets,
            popup: Popup::None,
            config,
            profile,
            available_profiles,
            profile_picker_index: 0,
            providers,
            provider_index: 0,
            secrets,
            secret_index: 0,
            resolved_values: IndexMap::new(),
            loading_secrets: HashSet::new(),
            initial_loading: true,
            current_resolution_id: 0,
            error_message: None,
            status_message: None,
            search_filter: String::new(),
            searching: false,
            show_values: false,
            event_tx: None,
            providers_area: Rect::default(),
            secrets_area: Rect::default(),
            providers_scroll_offset: 0,
            secrets_scroll_offset: 0,
        })
    }

    /// Set the event channel sender
    pub fn set_event_tx(&mut self, tx: mpsc::UnboundedSender<Event>) {
        self.event_tx = Some(tx);
    }

    /// Get byte index from character index (UTF-8 safe)
    fn char_to_byte_index(s: &str, char_idx: usize) -> usize {
        s.char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(s.len())
    }

    /// Insert a character at a character position (UTF-8 safe)
    fn insert_char_at(s: &mut String, char_idx: usize, c: char) {
        let byte_idx = Self::char_to_byte_index(s, char_idx);
        s.insert(byte_idx, c);
    }

    /// Remove a character at a character position (UTF-8 safe)
    fn remove_char_at(s: &mut String, char_idx: usize) {
        let byte_idx = Self::char_to_byte_index(s, char_idx);
        if byte_idx < s.len() {
            s.remove(byte_idx);
        }
    }

    /// Get list of secret keys, filtered by search
    pub fn filtered_secrets(&self) -> Vec<&String> {
        if self.search_filter.is_empty() {
            self.secrets.keys().collect()
        } else {
            let filter = self.search_filter.to_lowercase();
            self.secrets
                .keys()
                .filter(|k| k.to_lowercase().contains(&filter))
                .collect()
        }
    }

    /// Get the currently selected secret key
    pub fn selected_secret(&self) -> Option<&String> {
        let filtered = self.filtered_secrets();
        filtered.get(self.secret_index).copied()
    }

    /// Spawn async task to resolve all secrets
    pub fn spawn_resolve_secrets(&mut self, tx: mpsc::UnboundedSender<Event>) {
        // Increment resolution ID to invalidate any in-flight resolutions
        self.current_resolution_id = self.current_resolution_id.wrapping_add(1);
        let resolution_id = self.current_resolution_id;

        // Clear stale resolved values to prevent showing wrong data
        self.resolved_values.clear();
        self.initial_loading = true;
        self.loading_secrets = self.secrets.keys().cloned().collect();

        let config = self.config.clone();
        let profile = self.profile.clone();
        let secrets = self.secrets.clone();

        tokio::spawn(async move {
            match resolve_secrets_batch(&config, &profile, &secrets).await {
                Ok(resolved) => {
                    let _ = tx.send(Event::Message(Message::SecretsResolved {
                        resolution_id,
                        resolved,
                    }));
                }
                Err(e) => {
                    let _ = tx.send(Event::Message(Message::Error {
                        resolution_id,
                        message: e.to_string(),
                    }));
                }
            }
        });
    }

    /// Handle an incoming message
    pub fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::SecretsResolved {
                resolution_id,
                resolved,
            } => {
                // Ignore results from stale resolution tasks (e.g., after profile switch)
                if resolution_id != self.current_resolution_id {
                    return;
                }
                self.resolved_values = resolved;
                self.loading_secrets.clear();
                self.initial_loading = false;
            }
            Message::Error {
                resolution_id,
                message,
            } => {
                // Ignore errors from stale resolution tasks
                if resolution_id != self.current_resolution_id {
                    return;
                }
                self.error_message = Some(message);
                self.loading_secrets.clear();
                self.initial_loading = false;
            }
        }
    }

    /// Handle a key event
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Clear status message on any keypress
        self.status_message = None;

        // Clear error on any keypress
        if self.error_message.is_some() && self.popup == Popup::None && !self.searching {
            self.error_message = None;
            return;
        }

        // Handle popup modes first
        match &self.popup {
            Popup::Help => {
                // Any key closes help
                self.popup = Popup::None;
                return;
            }
            Popup::ProfilePicker => {
                self.handle_profile_picker_key(key);
                return;
            }
            Popup::SecretDetail(secret_key) => {
                // Handle copy, otherwise close
                match key.code {
                    KeyCode::Char('c') => {
                        // Copy the secret value
                        if let Some(Some(value)) = self.resolved_values.get(secret_key) {
                            match arboard::Clipboard::new() {
                                Ok(mut clipboard) => {
                                    if let Err(e) = clipboard.set_text(value.clone()) {
                                        self.error_message = Some(format!("Failed to copy: {}", e));
                                    } else {
                                        self.status_message = Some("Copied!".to_string());
                                    }
                                }
                                Err(e) => {
                                    self.error_message =
                                        Some(format!("Clipboard not available: {}", e));
                                }
                            }
                        } else {
                            self.error_message = Some("Secret value not available".to_string());
                        }
                        self.popup = Popup::None;
                    }
                    _ => {
                        self.popup = Popup::None;
                    }
                }
                return;
            }
            Popup::ConfirmDelete(secret_key) => {
                self.handle_confirm_delete_key(key, secret_key.clone());
                return;
            }
            Popup::EditSecret(_) => {
                self.handle_edit_secret_key(key);
                return;
            }
            Popup::SetSecret(_) => {
                self.handle_set_secret_key(key);
                return;
            }
            Popup::None => {}
        }

        // Handle search mode
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search_filter.clear();
                    self.secret_index = 0;
                }
                KeyCode::Enter => {
                    self.searching = false;
                }
                KeyCode::Backspace => {
                    self.search_filter.pop();
                    self.secret_index = 0;
                }
                KeyCode::Char(c) => {
                    self.search_filter.push(c);
                    self.secret_index = 0;
                }
                _ => {}
            }
            return;
        }

        // Normal mode
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.running = false;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.running = false;
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Providers => Focus::Secrets,
                    Focus::Secrets => Focus::Providers,
                };
            }
            KeyCode::Char('/') => {
                self.searching = true;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
            }
            KeyCode::Char('g') => {
                // Go to top
                match self.focus {
                    Focus::Providers => self.provider_index = 0,
                    Focus::Secrets => self.secret_index = 0,
                }
            }
            KeyCode::Char('G') => {
                // Go to bottom
                match self.focus {
                    Focus::Providers => {
                        if !self.providers.is_empty() {
                            self.provider_index = self.providers.len() - 1;
                        }
                    }
                    Focus::Secrets => {
                        let filtered = self.filtered_secrets();
                        if !filtered.is_empty() {
                            self.secret_index = filtered.len() - 1;
                        }
                    }
                }
            }
            KeyCode::Char('?') => {
                self.popup = Popup::Help;
            }
            KeyCode::Char('P') => {
                // Open profile picker
                self.profile_picker_index = self
                    .available_profiles
                    .iter()
                    .position(|p| p == &self.profile)
                    .unwrap_or(0);
                self.popup = Popup::ProfilePicker;
            }
            KeyCode::Char('r') => {
                // Refresh - reload secrets
                self.refresh();
            }
            KeyCode::Char('c') => {
                // Copy secret value to clipboard
                self.copy_selected_secret();
            }
            KeyCode::Enter => {
                // Show secret detail view
                if self.focus == Focus::Secrets
                    && let Some(key) = self.selected_secret()
                {
                    self.popup = Popup::SecretDetail(key.clone());
                }
            }
            KeyCode::Char('d') => {
                // Delete secret (with confirmation)
                if self.focus == Focus::Secrets
                    && let Some(key) = self.selected_secret()
                {
                    self.popup = Popup::ConfirmDelete(key.clone());
                }
            }
            KeyCode::Char('e') => {
                // Edit selected secret value
                if self.focus == Focus::Secrets {
                    self.open_edit_secret();
                }
            }
            KeyCode::Char('s') => {
                // Set/create a new secret
                self.popup = Popup::SetSecret(SetState {
                    key: String::new(),
                    value: String::new(),
                    field: SetField::Key,
                    cursor: 0,
                });
            }
            KeyCode::Char('V') => {
                // Toggle showing secret values
                self.show_values = !self.show_values;
            }
            _ => {}
        }
    }

    /// Handle a mouse event
    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        // Ignore mouse events when popup is open (except for dismissing)
        if self.popup != Popup::None {
            if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                // Click dismisses most popups
                match &self.popup {
                    Popup::Help | Popup::SecretDetail(_) => {
                        self.popup = Popup::None;
                    }
                    _ => {}
                }
            }
            return;
        }

        // Clear status message on mouse activity
        self.status_message = None;

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let x = mouse.column;
                let y = mouse.row;

                // Check if click is in providers area
                if self.is_in_area(x, y, self.providers_area) {
                    self.focus = Focus::Providers;
                    // Calculate which item was clicked (accounting for border and scroll)
                    let relative_y = y.saturating_sub(self.providers_area.y + 1);
                    let actual_index = self.providers_scroll_offset + relative_y as usize;
                    if actual_index < self.providers.len() {
                        self.provider_index = actual_index;
                    }
                }
                // Check if click is in secrets area
                else if self.is_in_area(x, y, self.secrets_area) {
                    self.focus = Focus::Secrets;
                    // Calculate which item was clicked (accounting for border and scroll)
                    let relative_y = y.saturating_sub(self.secrets_area.y + 1);
                    let actual_index = self.secrets_scroll_offset + relative_y as usize;
                    let filtered = self.filtered_secrets();
                    if actual_index < filtered.len() {
                        self.secret_index = actual_index;
                    }
                }
            }
            MouseEventKind::ScrollDown => {
                self.move_selection(1);
            }
            MouseEventKind::ScrollUp => {
                self.move_selection(-1);
            }
            _ => {}
        }
    }

    /// Check if coordinates are within a given area
    fn is_in_area(&self, x: u16, y: u16, area: Rect) -> bool {
        x >= area.x && x < area.x + area.width && y >= area.y && y < area.y + area.height
    }

    /// Copy selected secret value to clipboard
    fn copy_selected_secret(&mut self) {
        if self.focus != Focus::Secrets {
            return;
        }

        let Some(key) = self.selected_secret().cloned() else {
            return;
        };

        // Check if secret is resolved
        let Some(Some(value)) = self.resolved_values.get(&key) else {
            self.error_message = Some("Secret value not available".to_string());
            return;
        };

        // Copy to clipboard
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => {
                if let Err(e) = clipboard.set_text(value.clone()) {
                    self.error_message = Some(format!("Failed to copy: {}", e));
                } else {
                    self.status_message = Some("Copied!".to_string());
                }
            }
            Err(e) => {
                self.error_message = Some(format!("Clipboard not available: {}", e));
            }
        }
    }

    /// Handle keys in confirm delete popup
    fn handle_confirm_delete_key(&mut self, key: KeyEvent, _secret_key: String) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.popup = Popup::None;
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                // Note: Actual deletion would require modifying the config file
                // For now, we just show a message that this feature isn't implemented
                self.error_message = Some("Delete not yet implemented in TUI".to_string());
                self.popup = Popup::None;
            }
            _ => {}
        }
    }

    /// Open edit dialog for selected secret
    fn open_edit_secret(&mut self) {
        let Some(key) = self.selected_secret().cloned() else {
            return;
        };

        // Get current value if resolved
        let current_value = self
            .resolved_values
            .get(&key)
            .and_then(|v| v.clone())
            .unwrap_or_default();

        let cursor = current_value.chars().count();
        self.popup = Popup::EditSecret(EditState {
            key,
            value: current_value,
            cursor,
        });
    }

    /// Handle keys in edit secret popup
    fn handle_edit_secret_key(&mut self, key: KeyEvent) {
        let Popup::EditSecret(ref mut state) = self.popup else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                self.popup = Popup::None;
            }
            KeyCode::Enter => {
                // Save the edited value
                let key = state.key.clone();
                let value = state.value.clone();
                self.popup = Popup::None;

                // Note: Actually saving would require modifying the config file
                // For now, just update the in-memory resolved value
                self.resolved_values.insert(key.clone(), Some(value));
                self.status_message = Some(format!("Updated {} (in memory only)", key));
            }
            KeyCode::Backspace => {
                if state.cursor > 0 {
                    Self::remove_char_at(&mut state.value, state.cursor - 1);
                    state.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if state.cursor < state.value.chars().count() {
                    Self::remove_char_at(&mut state.value, state.cursor);
                }
            }
            KeyCode::Left => {
                state.cursor = state.cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                state.cursor = (state.cursor + 1).min(state.value.chars().count());
            }
            KeyCode::Home => {
                state.cursor = 0;
            }
            KeyCode::End => {
                state.cursor = state.value.chars().count();
            }
            KeyCode::Char(c) => {
                Self::insert_char_at(&mut state.value, state.cursor, c);
                state.cursor += 1;
            }
            _ => {}
        }
    }

    /// Handle keys in set secret popup
    fn handle_set_secret_key(&mut self, key: KeyEvent) {
        let Popup::SetSecret(ref mut state) = self.popup else {
            return;
        };

        // Clear error on any keypress except Esc (which closes the popup)
        if key.code != KeyCode::Esc {
            self.error_message = None;
        }

        match key.code {
            KeyCode::Esc => {
                self.popup = Popup::None;
            }
            KeyCode::Tab => {
                // Switch between key and value fields
                state.field = match state.field {
                    SetField::Key => {
                        state.cursor = state.value.chars().count();
                        SetField::Value
                    }
                    SetField::Value => {
                        state.cursor = state.key.chars().count();
                        SetField::Key
                    }
                };
            }
            KeyCode::Enter => {
                if state.key.is_empty() {
                    self.error_message = Some("Secret key cannot be empty".to_string());
                    return;
                }

                // Save the new secret
                let key = state.key.clone();
                let value = state.value.clone();
                self.popup = Popup::None;

                // Note: Actually saving would require modifying the config file
                // For now, just update the in-memory state
                let mut secret_config = SecretConfig::new();
                secret_config.value = Some(value.clone());
                self.secrets.insert(key.clone(), secret_config);
                self.resolved_values.insert(key.clone(), Some(value));
                self.status_message = Some(format!("Set {} (in memory only)", key));
            }
            KeyCode::Backspace => {
                if state.cursor > 0 {
                    let field = match state.field {
                        SetField::Key => &mut state.key,
                        SetField::Value => &mut state.value,
                    };
                    Self::remove_char_at(field, state.cursor - 1);
                    state.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                let field = match state.field {
                    SetField::Key => &mut state.key,
                    SetField::Value => &mut state.value,
                };
                if state.cursor < field.chars().count() {
                    Self::remove_char_at(field, state.cursor);
                }
            }
            KeyCode::Left => {
                state.cursor = state.cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                let max = match state.field {
                    SetField::Key => state.key.chars().count(),
                    SetField::Value => state.value.chars().count(),
                };
                state.cursor = (state.cursor + 1).min(max);
            }
            KeyCode::Char(c) => {
                let field = match state.field {
                    SetField::Key => &mut state.key,
                    SetField::Value => &mut state.value,
                };
                Self::insert_char_at(field, state.cursor, c);
                state.cursor += 1;
            }
            _ => {}
        }
    }

    /// Handle keys in profile picker popup
    fn handle_profile_picker_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.popup = Popup::None;
            }
            KeyCode::Enter => {
                // Select the profile
                if let Some(profile) = self.available_profiles.get(self.profile_picker_index) {
                    self.switch_profile(profile.clone());
                }
                self.popup = Popup::None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.available_profiles.is_empty() {
                    self.profile_picker_index =
                        (self.profile_picker_index + 1) % self.available_profiles.len();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.available_profiles.is_empty() {
                    self.profile_picker_index = self
                        .profile_picker_index
                        .checked_sub(1)
                        .unwrap_or(self.available_profiles.len() - 1);
                }
            }
            _ => {}
        }
    }

    /// Switch to a different profile
    fn switch_profile(&mut self, new_profile: String) {
        if new_profile == self.profile {
            return;
        }

        // Try to load secrets first before committing to the change
        match self.config.get_secrets(&new_profile) {
            Ok(secrets) => {
                // Success - now update all state
                self.profile = new_profile;
                self.providers = self
                    .config
                    .get_providers(&self.profile)
                    .keys()
                    .cloned()
                    .collect();
                self.provider_index = 0;
                self.secrets = secrets;
                self.secret_index = 0;
                self.search_filter.clear();
                self.refresh();
            }
            Err(e) => {
                // Failed - don't change anything, just show error
                self.error_message = Some(format!("Failed to load profile: {}", e));
            }
        }
    }

    /// Refresh secrets by re-resolving them
    fn refresh(&mut self) {
        if let Some(tx) = &self.event_tx {
            self.spawn_resolve_secrets(tx.clone());
        }
    }

    fn move_selection(&mut self, delta: i32) {
        match self.focus {
            Focus::Providers => {
                if self.providers.is_empty() {
                    return;
                }
                let new_index = self.provider_index as i32 + delta;
                self.provider_index = new_index.clamp(0, self.providers.len() as i32 - 1) as usize;
            }
            Focus::Secrets => {
                let filtered = self.filtered_secrets();
                if filtered.is_empty() {
                    return;
                }
                let new_index = self.secret_index as i32 + delta;
                self.secret_index = new_index.clamp(0, filtered.len() as i32 - 1) as usize;
            }
        }
    }
}
