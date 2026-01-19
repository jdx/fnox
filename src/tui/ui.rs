//! UI rendering

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};

use crate::tui::app::{App, EditState, Focus, Popup, SetField, SetState};

/// Color palette that respects --no-color flag
struct Colors;

impl Colors {
    fn enabled() -> bool {
        console::colors_enabled()
    }

    fn cyan() -> Color {
        if Self::enabled() {
            Color::Cyan
        } else {
            Color::Reset
        }
    }

    fn yellow() -> Color {
        if Self::enabled() {
            Color::Yellow
        } else {
            Color::Reset
        }
    }

    fn green() -> Color {
        if Self::enabled() {
            Color::Green
        } else {
            Color::Reset
        }
    }

    fn red() -> Color {
        if Self::enabled() {
            Color::Red
        } else {
            Color::Reset
        }
    }

    fn dark_gray() -> Color {
        if Self::enabled() {
            Color::DarkGray
        } else {
            Color::Reset
        }
    }

    fn white() -> Color {
        if Self::enabled() {
            Color::White
        } else {
            Color::Reset
        }
    }
}

/// Render the entire UI
pub fn render(app: &mut App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Status bar
            Constraint::Length(1), // Keybindings
        ])
        .split(frame.area());

    render_header(app, frame, chunks[0]);
    render_main(app, frame, chunks[1]);
    render_status(app, frame, chunks[2]);
    render_keybindings(app, frame, chunks[3]);

    // Render popups
    match &app.popup {
        Popup::Help => render_help_popup(frame),
        Popup::ProfilePicker => render_profile_picker(app, frame),
        Popup::SecretDetail(key) => render_secret_detail(app, frame, key),
        Popup::ConfirmDelete(key) => render_confirm_delete(frame, key),
        Popup::EditSecret(state) => render_edit_secret(frame, state),
        Popup::SetSecret(state) => render_set_secret(frame, state),
        Popup::None => {}
    }

    // Render error popup if present (on top of everything)
    if let Some(ref error) = app.error_message {
        render_error_popup(frame, error);
    }
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let title = format!(" fnox - Secrets Dashboard │ Profile: {} ", app.profile);

    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Colors::cyan())
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    frame.render_widget(header, area);
}

fn render_main(app: &mut App, frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(area);

    // Save layout areas for mouse click detection
    app.providers_area = chunks[0];
    app.secrets_area = chunks[1];

    render_providers(app, frame, chunks[0]);
    render_secrets(app, frame, chunks[1]);
}

fn render_providers(app: &mut App, frame: &mut Frame, area: Rect) {
    let is_focused = app.focus == Focus::Providers;

    let items: Vec<ListItem> = app
        .providers
        .iter()
        .map(|name| ListItem::new(name.as_str()))
        .collect();

    let border_style = if is_focused {
        Style::default().fg(Colors::cyan())
    } else {
        Style::default().fg(Colors::dark_gray())
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Providers ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Colors::yellow()),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if !app.providers.is_empty() {
        state.select(Some(app.provider_index));
    }

    frame.render_stateful_widget(list, area, &mut state);

    // Save scroll offset for mouse click handling
    app.providers_scroll_offset = state.offset();
}

fn render_secrets(app: &mut App, frame: &mut Frame, area: Rect) {
    let is_focused = app.focus == Focus::Secrets;
    let filtered = app.filtered_secrets();

    let items: Vec<ListItem> = filtered
        .iter()
        .map(|key| {
            let secret_config = &app.secrets[*key];

            // Get provider name
            let provider = secret_config.provider.as_deref().unwrap_or("env");

            // Get value status
            let value_status = if app.loading_secrets.contains(*key) || app.initial_loading {
                Span::styled("loading...", Style::default().fg(Colors::yellow()))
            } else if let Some(Some(value)) = app.resolved_values.get(*key) {
                if app.show_values {
                    // Truncate long values for display (UTF-8 safe)
                    let display_val: String = if value.chars().count() > 40 {
                        format!("{}...", value.chars().take(37).collect::<String>())
                    } else {
                        value.clone()
                    };
                    Span::styled(display_val, Style::default().fg(Colors::green()))
                } else {
                    Span::styled("******", Style::default().fg(Colors::green()))
                }
            } else {
                Span::styled("<not set>", Style::default().fg(Colors::red()))
            };

            let line = Line::from(vec![
                Span::raw(format!("{:<30}", key)),
                Span::styled(
                    format!("{:<15}", provider),
                    Style::default().fg(Colors::cyan()),
                ),
                value_status,
            ]);

            ListItem::new(line)
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(Colors::cyan())
    } else {
        Style::default().fg(Colors::dark_gray())
    };

    let title = if app.searching {
        format!(" Secrets (/{}) ", app.search_filter)
    } else if !app.search_filter.is_empty() {
        format!(" Secrets [filtered: {}] ", app.search_filter)
    } else {
        " Secrets ".to_string()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Colors::dark_gray()),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if !filtered.is_empty() {
        state.select(Some(app.secret_index.min(filtered.len().saturating_sub(1))));
    }

    frame.render_stateful_widget(list, area, &mut state);

    // Save scroll offset for mouse click handling
    app.secrets_scroll_offset = state.offset();
}

fn render_status(app: &App, frame: &mut Frame, area: Rect) {
    let total = app.secrets.len();
    let loaded = app.resolved_values.values().filter(|v| v.is_some()).count();
    let filtered = app.filtered_secrets().len();

    // Build status text with optional status message
    let mut status_parts = Vec::new();

    if let Some(ref msg) = app.status_message {
        status_parts.push(Span::styled(
            format!("{} │ ", msg),
            Style::default()
                .fg(Colors::green())
                .add_modifier(Modifier::BOLD),
        ));
    }

    let main_status = if app.initial_loading {
        format!("Loading secrets... | Total: {}", total)
    } else if filtered != total {
        format!(
            "Showing: {} of {} | Loaded: {} | Total: {}",
            filtered, total, loaded, total
        )
    } else {
        format!("Loaded: {} | Total: {}", loaded, total)
    };

    status_parts.push(Span::raw(main_status));

    let status_bar = Paragraph::new(Line::from(status_parts))
        .style(Style::default().fg(Colors::white()))
        .block(Block::default().borders(Borders::ALL).title(" Status "));

    frame.render_widget(status_bar, area);
}

fn render_keybindings(app: &App, frame: &mut Frame, area: Rect) {
    let show_hide = if app.show_values { "Hide" } else { "Show" };
    let bindings = Line::from(vec![
        Span::styled(" q", Style::default().fg(Colors::yellow())),
        Span::raw(" Quit  "),
        Span::styled("j/k", Style::default().fg(Colors::yellow())),
        Span::raw(" Nav  "),
        Span::styled("V", Style::default().fg(Colors::yellow())),
        Span::raw(format!(" {}  ", show_hide)),
        Span::styled("c", Style::default().fg(Colors::yellow())),
        Span::raw(" Copy  "),
        Span::styled("e", Style::default().fg(Colors::yellow())),
        Span::raw(" Edit  "),
        Span::styled("s", Style::default().fg(Colors::yellow())),
        Span::raw(" Set  "),
        Span::styled("/", Style::default().fg(Colors::yellow())),
        Span::raw(" Search  "),
        Span::styled("?", Style::default().fg(Colors::yellow())),
        Span::raw(" Help"),
    ]);

    let keybindings = Paragraph::new(bindings).style(Style::default().fg(Colors::dark_gray()));

    frame.render_widget(keybindings, area);
}

fn render_error_popup(frame: &mut Frame, error: &str) {
    let area = centered_rect(60, 20, frame.area());

    let error_block = Paragraph::new(error)
        .style(Style::default().fg(Colors::red()))
        .block(
            Block::default()
                .title(" Error (press any key to dismiss) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Colors::red())),
        );

    frame.render_widget(Clear, area);
    frame.render_widget(error_block, area);
}

fn render_help_popup(frame: &mut Frame) {
    let area = centered_rect(50, 80, frame.area());

    let help_text = vec![
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Colors::cyan()),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  j/↓  ", Style::default().fg(Colors::yellow())),
            Span::raw("Move down"),
        ]),
        Line::from(vec![
            Span::styled("  k/↑  ", Style::default().fg(Colors::yellow())),
            Span::raw("Move up"),
        ]),
        Line::from(vec![
            Span::styled("  g    ", Style::default().fg(Colors::yellow())),
            Span::raw("Go to top"),
        ]),
        Line::from(vec![
            Span::styled("  G    ", Style::default().fg(Colors::yellow())),
            Span::raw("Go to bottom"),
        ]),
        Line::from(vec![
            Span::styled("  Tab  ", Style::default().fg(Colors::yellow())),
            Span::raw("Switch panel"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Search & Filter",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Colors::cyan()),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  /    ", Style::default().fg(Colors::yellow())),
            Span::raw("Start search"),
        ]),
        Line::from(vec![
            Span::styled("  Esc  ", Style::default().fg(Colors::yellow())),
            Span::raw("Clear search"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Secret Actions",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Colors::cyan()),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Colors::yellow())),
            Span::raw(" View secret details"),
        ]),
        Line::from(vec![
            Span::styled("  c    ", Style::default().fg(Colors::yellow())),
            Span::raw("Copy value to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("  V    ", Style::default().fg(Colors::yellow())),
            Span::raw("Toggle show/hide values"),
        ]),
        Line::from(vec![
            Span::styled("  e    ", Style::default().fg(Colors::yellow())),
            Span::raw("Edit secret value"),
        ]),
        Line::from(vec![
            Span::styled("  s    ", Style::default().fg(Colors::yellow())),
            Span::raw("Set new secret"),
        ]),
        Line::from(vec![
            Span::styled("  d    ", Style::default().fg(Colors::yellow())),
            Span::raw("Delete secret"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Colors::cyan()),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  P    ", Style::default().fg(Colors::yellow())),
            Span::raw("Switch profile"),
        ]),
        Line::from(vec![
            Span::styled("  r    ", Style::default().fg(Colors::yellow())),
            Span::raw("Refresh secrets"),
        ]),
        Line::from(vec![
            Span::styled("  q    ", Style::default().fg(Colors::yellow())),
            Span::raw("Quit"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "       Press any key to close",
            Style::default().fg(Colors::dark_gray()),
        )]),
    ];

    let help_block = Paragraph::new(help_text).block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Colors::cyan())),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(help_block, area);
}

fn render_profile_picker(app: &App, frame: &mut Frame) {
    let height = (app.available_profiles.len() + 4).min(15) as u16;
    let area = centered_rect(40, height * 3, frame.area());

    let items: Vec<ListItem> = app
        .available_profiles
        .iter()
        .map(|name| {
            let style = if name == &app.profile {
                Style::default()
                    .fg(Colors::green())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(format!("  {}", name)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Select Profile ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Colors::cyan())),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Colors::dark_gray()),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(app.profile_picker_index));

    frame.render_widget(Clear, area);
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_secret_detail(app: &App, frame: &mut Frame, secret_key: &str) {
    let area = centered_rect(70, 50, frame.area());

    let secret_config = app.secrets.get(secret_key);
    let resolved_value = app.resolved_values.get(secret_key);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Key: ", Style::default().fg(Colors::cyan())),
            Span::styled(secret_key, Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
    ];

    if let Some(config) = secret_config {
        // Provider
        if let Some(ref provider) = config.provider {
            lines.push(Line::from(vec![
                Span::styled("Provider: ", Style::default().fg(Colors::cyan())),
                Span::raw(provider.as_str()),
            ]));
        }

        // Provider key/value
        if let Some(ref value) = config.value {
            lines.push(Line::from(vec![
                Span::styled("Provider Key: ", Style::default().fg(Colors::cyan())),
                Span::raw(value.as_str()),
            ]));
        }

        // Description
        if let Some(ref desc) = config.description {
            lines.push(Line::from(vec![
                Span::styled("Description: ", Style::default().fg(Colors::cyan())),
                Span::raw(desc.as_str()),
            ]));
        }

        // Default
        if let Some(ref default) = config.default {
            lines.push(Line::from(vec![
                Span::styled("Default: ", Style::default().fg(Colors::cyan())),
                Span::raw(default.as_str()),
            ]));
        }

        // If missing behavior
        if let Some(if_missing) = config.if_missing {
            lines.push(Line::from(vec![
                Span::styled("If Missing: ", Style::default().fg(Colors::cyan())),
                Span::raw(format!("{:?}", if_missing)),
            ]));
        }

        // Source path
        if let Some(ref path) = config.source_path {
            lines.push(Line::from(vec![
                Span::styled("Source: ", Style::default().fg(Colors::cyan())),
                Span::raw(path.display().to_string()),
            ]));
        }
    }

    lines.push(Line::from(""));

    // Resolved value status
    match resolved_value {
        Some(Some(val)) => {
            lines.push(Line::from(vec![
                Span::styled("Value: ", Style::default().fg(Colors::cyan())),
                Span::styled(
                    format!("({} chars)", val.chars().count()),
                    Style::default().fg(Colors::green()),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("       Press ", Style::default().fg(Colors::dark_gray())),
                Span::styled("c", Style::default().fg(Colors::yellow())),
                Span::styled(" to copy value", Style::default().fg(Colors::dark_gray())),
            ]));
        }
        Some(None) => {
            lines.push(Line::from(vec![
                Span::styled("Value: ", Style::default().fg(Colors::cyan())),
                Span::styled("<not set>", Style::default().fg(Colors::red())),
            ]));
        }
        None => {
            lines.push(Line::from(vec![
                Span::styled("Value: ", Style::default().fg(Colors::cyan())),
                Span::styled("<loading...>", Style::default().fg(Colors::yellow())),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "       Press any key to close",
        Style::default().fg(Colors::dark_gray()),
    )]));

    let detail_block = Paragraph::new(lines).block(
        Block::default()
            .title(" Secret Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Colors::cyan())),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(detail_block, area);
}

fn render_confirm_delete(frame: &mut Frame, secret_key: &str) {
    let area = centered_rect(50, 25, frame.area());

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  Delete secret "),
            Span::styled(
                secret_key,
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Colors::yellow()),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
        Line::from("  This will remove the secret from your config file."),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Press "),
            Span::styled(
                "y",
                Style::default()
                    .fg(Colors::green())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to confirm, "),
            Span::styled(
                "n",
                Style::default()
                    .fg(Colors::red())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" or "),
            Span::styled(
                "Esc",
                Style::default()
                    .fg(Colors::red())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to cancel"),
        ]),
    ];

    let confirm_block = Paragraph::new(lines).block(
        Block::default()
            .title(" Confirm Delete ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Colors::red())),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(confirm_block, area);
}

fn render_edit_secret(frame: &mut Frame, state: &EditState) {
    let area = centered_rect(60, 30, frame.area());

    // Create input display with cursor (UTF-8 safe using char indices)
    let char_count = state.value.chars().count();
    let cursor_pos = state.cursor.min(char_count);
    let before: String = state.value.chars().take(cursor_pos).collect();
    let cursor_char = state.value.chars().nth(cursor_pos).unwrap_or(' ');
    let after_cursor: String = state.value.chars().skip(cursor_pos + 1).collect();

    let input_line = Line::from(vec![
        Span::raw(before),
        Span::styled(
            cursor_char.to_string(),
            Style::default().bg(Colors::white()).fg(Color::Black),
        ),
        Span::raw(after_cursor),
    ]);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Key: ", Style::default().fg(Colors::cyan())),
            Span::styled(&state.key, Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Value: ",
            Style::default().fg(Colors::cyan()),
        )]),
        Line::from(vec![
            Span::raw("  "),
            input_line.spans[0].clone(),
            input_line.spans[1].clone(),
            input_line.spans[2].clone(),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(Colors::yellow())),
            Span::raw(" Save  "),
            Span::styled("Esc", Style::default().fg(Colors::yellow())),
            Span::raw(" Cancel"),
        ]),
    ];

    let edit_block = Paragraph::new(lines).block(
        Block::default()
            .title(" Edit Secret ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Colors::cyan())),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(edit_block, area);
}

fn render_set_secret(frame: &mut Frame, state: &SetState) {
    let area = centered_rect(60, 35, frame.area());

    let key_active = state.field == SetField::Key;
    let value_active = state.field == SetField::Value;

    let key_style = if key_active {
        Style::default()
            .fg(Colors::cyan())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Colors::dark_gray())
    };
    let value_style = if value_active {
        Style::default()
            .fg(Colors::cyan())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Colors::dark_gray())
    };

    // Render key input (UTF-8 safe using char indices)
    let key_line = if key_active {
        let char_count = state.key.chars().count();
        let cursor_pos = state.cursor.min(char_count);
        let before: String = state.key.chars().take(cursor_pos).collect();
        let cursor_char = state.key.chars().nth(cursor_pos).unwrap_or(' ');
        let after_cursor: String = state.key.chars().skip(cursor_pos + 1).collect();
        Line::from(vec![
            Span::raw("  "),
            Span::raw(before),
            Span::styled(
                cursor_char.to_string(),
                Style::default().bg(Colors::white()).fg(Color::Black),
            ),
            Span::raw(after_cursor),
        ])
    } else {
        Line::from(vec![Span::raw(format!("  {}", state.key))])
    };

    // Render value input (UTF-8 safe using char indices)
    let value_line = if value_active {
        let char_count = state.value.chars().count();
        let cursor_pos = state.cursor.min(char_count);
        let before: String = state.value.chars().take(cursor_pos).collect();
        let cursor_char = state.value.chars().nth(cursor_pos).unwrap_or(' ');
        let after_cursor: String = state.value.chars().skip(cursor_pos + 1).collect();
        Line::from(vec![
            Span::raw("  "),
            Span::raw(before),
            Span::styled(
                cursor_char.to_string(),
                Style::default().bg(Colors::white()).fg(Color::Black),
            ),
            Span::raw(after_cursor),
        ])
    } else {
        Line::from(vec![Span::raw(format!("  {}", state.value))])
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled("  Key: ", key_style)]),
        key_line,
        Line::from(""),
        Line::from(vec![Span::styled("  Value: ", value_style)]),
        value_line,
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tab", Style::default().fg(Colors::yellow())),
            Span::raw(" Switch field  "),
            Span::styled("Enter", Style::default().fg(Colors::yellow())),
            Span::raw(" Save  "),
            Span::styled("Esc", Style::default().fg(Colors::yellow())),
            Span::raw(" Cancel"),
        ]),
    ];

    let set_block = Paragraph::new(lines).block(
        Block::default()
            .title(" Set Secret ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Colors::cyan())),
    );

    frame.render_widget(Clear, area);
    frame.render_widget(set_block, area);
}

/// Helper to create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
