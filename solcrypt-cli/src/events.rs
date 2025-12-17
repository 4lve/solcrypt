//! Event handling for keyboard input.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

use crate::app::{App, InputMode, Screen};

/// Result type for event handling
pub enum EventResult {
    /// Continue normally
    Continue,
    /// Refresh chats
    RefreshChats,
    /// Open selected chat
    OpenChat,
    /// Send message with content
    SendMessage(String),
    /// Start new chat with recipient
    StartNewChat(String),
    /// Accept pending chat
    AcceptChat,
    /// Load messages for current chat
    LoadMessages,
}

/// Poll for events with timeout
pub fn poll_event(timeout: Duration) -> std::io::Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Handle keyboard events based on current screen
pub fn handle_key_event(app: &mut App, key: KeyEvent) -> EventResult {
    // Global quit with Ctrl+C
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return EventResult::Continue;
    }

    match &app.screen {
        Screen::ChatList => handle_chat_list_keys(app, key),
        Screen::Chat { .. } => handle_chat_keys(app, key),
        Screen::NewChat => handle_new_chat_keys(app, key),
        Screen::Loading { .. } => EventResult::Continue,
        Screen::Error { .. } => {
            // Any key dismisses error
            app.go_back();
            EventResult::Continue
        }
    }
}

/// Handle keys in chat list screen
fn handle_chat_list_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Char('q') => {
            app.should_quit = true;
            EventResult::Continue
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_prev();
            EventResult::Continue
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_next();
            EventResult::Continue
        }
        KeyCode::Enter => {
            if app.total_chats() > 0 {
                EventResult::OpenChat
            } else {
                EventResult::Continue
            }
        }
        KeyCode::Char('n') => {
            app.navigate_to(Screen::NewChat);
            app.input_mode = InputMode::Editing;
            EventResult::Continue
        }
        KeyCode::Char('r') => EventResult::RefreshChats,
        KeyCode::Char('a') => {
            // Accept pending chat
            if let Some(chat) = app.get_selected_chat() {
                if !chat.is_accepted {
                    return EventResult::AcceptChat;
                }
            }
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

/// Handle keys in chat view
fn handle_chat_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match app.input_mode {
        InputMode::Normal => match key.code {
            KeyCode::Char('q') => {
                app.should_quit = true;
                EventResult::Continue
            }
            KeyCode::Esc => {
                app.navigate_to(Screen::ChatList);
                EventResult::RefreshChats
            }
            KeyCode::Char('i') => {
                app.input_mode = InputMode::Editing;
                EventResult::Continue
            }
            KeyCode::Char('r') => EventResult::LoadMessages,
            KeyCode::Up | KeyCode::Char('k') => {
                app.scroll_up();
                EventResult::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.scroll_down();
                EventResult::Continue
            }
            _ => EventResult::Continue,
        },
        InputMode::Editing => match key.code {
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.input.clear();
                app.cursor_position = 0;
                EventResult::Continue
            }
            KeyCode::Enter => {
                if !app.input.is_empty() {
                    let message = app.input.clone();
                    app.input.clear();
                    app.cursor_position = 0;
                    app.input_mode = InputMode::Normal;
                    EventResult::SendMessage(message)
                } else {
                    EventResult::Continue
                }
            }
            KeyCode::Char(c) => {
                app.enter_char(c);
                EventResult::Continue
            }
            KeyCode::Backspace => {
                app.delete_char();
                EventResult::Continue
            }
            KeyCode::Left => {
                app.move_cursor_left();
                EventResult::Continue
            }
            KeyCode::Right => {
                app.move_cursor_right();
                EventResult::Continue
            }
            _ => EventResult::Continue,
        },
    }
}

/// Handle keys in new chat dialog
fn handle_new_chat_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.go_back();
            EventResult::Continue
        }
        KeyCode::Enter => {
            if !app.input.is_empty() {
                let recipient = app.input.clone();
                app.input.clear();
                app.cursor_position = 0;
                EventResult::StartNewChat(recipient)
            } else {
                EventResult::Continue
            }
        }
        KeyCode::Char(c) => {
            app.enter_char(c);
            EventResult::Continue
        }
        KeyCode::Backspace => {
            app.delete_char();
            EventResult::Continue
        }
        KeyCode::Left => {
            app.move_cursor_left();
            EventResult::Continue
        }
        KeyCode::Right => {
            app.move_cursor_right();
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}
