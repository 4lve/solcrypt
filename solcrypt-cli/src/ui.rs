//! UI rendering with ratatui.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::app::{App, InputMode, Screen};
use crate::client::format_pubkey;

/// Render the application UI
pub fn render(frame: &mut Frame, app: &App) {
    match &app.screen {
        Screen::ChatList => render_chat_list(frame, app),
        Screen::Chat { recipient } => render_chat(frame, app, recipient),
        Screen::NewChat => render_new_chat(frame, app),
        Screen::Loading { message } => render_loading(frame, message),
        Screen::Error { message } => render_error(frame, message),
    }
}

/// Render the chat list screen
fn render_chat_list(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Chat list
            Constraint::Length(3), // Help
        ])
        .split(frame.area());

    // Header
    let header = Paragraph::new(format!(" Solcrypt - {}", format_pubkey(&app.user_pubkey)))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // Chat list
    let mut items: Vec<ListItem> = Vec::new();

    // Accepted chats section
    if !app.accepted_chats.is_empty() {
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "─── Chats ───",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )])));

        for (i, chat) in app.accepted_chats.iter().enumerate() {
            let selected = i == app.selected_chat;
            let style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            let text = format!(
                " {} {}",
                if selected { ">" } else { " " },
                format_pubkey(&chat.other_party)
            );
            items.push(ListItem::new(text).style(style));
        }
    }

    // Pending chats section
    if !app.pending_chats.is_empty() {
        items.push(ListItem::new("")); // Spacer
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "─── Pending Requests ───",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )])));

        for (i, chat) in app.pending_chats.iter().enumerate() {
            let idx = app.accepted_chats.len() + i;
            let selected = idx == app.selected_chat;
            let style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::Yellow)
            };

            let text = format!(
                " {} [NEW] {}",
                if selected { ">" } else { " " },
                format_pubkey(&chat.other_party)
            );
            items.push(ListItem::new(text).style(style));
        }
    }

    if items.is_empty() {
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "  No chats yet. Press 'n' to start a new conversation.",
            Style::default().fg(Color::DarkGray),
        )])));
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Conversations "),
    );
    frame.render_widget(list, chunks[1]);

    // Help text
    let help = Paragraph::new(" ↑/↓: Navigate | Enter: Open | n: New Chat | q: Quit")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

/// Render the chat view
fn render_chat(frame: &mut Frame, app: &App, recipient: &solana_sdk::pubkey::Pubkey) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Messages
            Constraint::Length(3), // Input
            Constraint::Length(1), // Help
        ])
        .split(frame.area());

    // Header
    let header = Paragraph::new(format!(" Chat with {}", format_pubkey(recipient)))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // Messages
    let mut message_items: Vec<ListItem> = Vec::new();

    for msg in &app.messages {
        let style = if msg.is_me {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Green)
        };

        let sender_label = if msg.is_me {
            "You".to_string()
        } else {
            format_pubkey(&msg.sender)
        };

        let line = Line::from(vec![
            Span::styled(
                format!("[{}] ", msg.timestamp_str),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}: ", sender_label),
                style.add_modifier(Modifier::BOLD),
            ),
            Span::raw(&msg.content),
        ]);

        message_items.push(ListItem::new(line));
    }

    if message_items.is_empty() {
        message_items.push(ListItem::new(Line::from(vec![Span::styled(
            "  No messages yet. Type a message below!",
            Style::default().fg(Color::DarkGray),
        )])));
    }

    let messages =
        List::new(message_items).block(Block::default().borders(Borders::ALL).title(" Messages "));
    frame.render_widget(messages, chunks[1]);

    // Input
    let input_style = match app.input_mode {
        InputMode::Normal => Style::default(),
        InputMode::Editing => Style::default().fg(Color::Yellow),
    };

    let input = Paragraph::new(app.input.as_str()).style(input_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title(if app.input_mode == InputMode::Editing {
                " Type message (Enter to send, Esc to cancel) "
            } else {
                " Press 'i' to type "
            }),
    );
    frame.render_widget(input, chunks[2]);

    // Set cursor position when editing
    if app.input_mode == InputMode::Editing {
        frame.set_cursor_position((
            chunks[2].x + app.cursor_position as u16 + 1,
            chunks[2].y + 1,
        ));
    }

    // Help
    let help_text = match app.input_mode {
        InputMode::Normal => "i: Type | r: Refresh | Esc: Back | q: Quit",
        InputMode::Editing => "Enter: Send | Esc: Cancel",
    };
    let help =
        Paragraph::new(format!(" {}", help_text)).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[3]);

    // Popup overlays
    if app.sending_message {
        render_sending_popup(frame);
    } else if app.refreshing {
        render_refreshing_popup(frame);
    }
}

/// Render sending message popup overlay
fn render_sending_popup(frame: &mut Frame) {
    let area = centered_rect(35, 15, frame.area());
    frame.render_widget(Clear, area);

    let popup = Paragraph::new(Text::from(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Sending message...  ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Sending "),
    );
    frame.render_widget(popup, area);
}

/// Render refreshing popup overlay
fn render_refreshing_popup(frame: &mut Frame) {
    let area = centered_rect(35, 15, frame.area());
    frame.render_widget(Clear, area);

    let popup = Paragraph::new(Text::from(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Refreshing...  ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Refresh "),
    );
    frame.render_widget(popup, area);
}

/// Render the new chat dialog
fn render_new_chat(frame: &mut Frame, app: &App) {
    let area = centered_rect(60, 20, frame.area());

    // Clear the background
    frame.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Input
            Constraint::Length(2), // Help
        ])
        .split(area);

    // Title
    let title = Paragraph::new(" Start New Conversation")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Input
    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Recipient Public Key "),
        );
    frame.render_widget(input, chunks[1]);

    // Set cursor
    frame.set_cursor_position((
        chunks[1].x + app.cursor_position as u16 + 1,
        chunks[1].y + 1,
    ));

    // Help
    let help = Paragraph::new(" Enter: Start Chat | Esc: Cancel")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[2]);
}

/// Render loading screen
fn render_loading(frame: &mut Frame, message: &str) {
    let area = centered_rect(40, 5, frame.area());
    frame.render_widget(Clear, area);

    let loading = Paragraph::new(format!(" {} ", message))
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title(" Loading "));
    frame.render_widget(loading, area);
}

/// Render error screen
fn render_error(frame: &mut Frame, message: &str) {
    let area = centered_rect(60, 10, frame.area());
    frame.render_widget(Clear, area);

    let error = Paragraph::new(Text::from(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(" {} ", message),
            Style::default().fg(Color::Red),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Press any key to continue ",
            Style::default().fg(Color::DarkGray),
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Error ")
            .style(Style::default().fg(Color::Red)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(error, area);
}

/// Helper function to create a centered rect
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
