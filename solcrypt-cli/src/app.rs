//! Application state and screen management for the TUI.

use solana_sdk::pubkey::Pubkey;
use solcrypt_program::MsgV1;

use crate::crypto::Message;

/// The current screen/view in the application
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    /// Chat list showing accepted and pending conversations
    ChatList,
    /// Active chat conversation view
    Chat { recipient: Pubkey },
    /// New chat dialog to enter recipient pubkey
    NewChat,
    /// Loading screen while performing async operations
    Loading { message: String },
    /// Error screen
    Error { message: String },
}

/// A chat thread with metadata for display
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChatThread {
    pub thread_id: [u8; 32],
    /// The other party in this conversation (resolved from messages)
    pub other_party: Pubkey,
    pub is_accepted: bool,
    pub last_message: Option<String>,
    pub unread: bool,
}

/// A message for display
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DisplayMessage {
    pub sender: Pubkey,
    pub is_me: bool,
    pub content: String,
    pub timestamp: i64,
    pub timestamp_str: String,
}

/// Input mode for text entry
#[derive(Debug, Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Editing,
}

/// Main application state
pub struct App {
    /// Current screen
    pub screen: Screen,
    /// Previous screen for back navigation
    pub prev_screen: Option<Screen>,
    /// Whether the app should quit
    pub should_quit: bool,
    /// Current input mode
    pub input_mode: InputMode,
    /// Current input buffer
    pub input: String,
    /// Cursor position in input
    pub cursor_position: usize,

    /// Accepted chat threads
    pub accepted_chats: Vec<ChatThread>,
    /// Pending chat threads
    pub pending_chats: Vec<ChatThread>,
    /// Currently selected chat index (in combined list)
    pub selected_chat: usize,

    /// Messages in current chat
    pub messages: Vec<DisplayMessage>,
    /// Scroll position in messages
    pub message_scroll: usize,

    /// Status message to show at bottom
    pub status: Option<String>,

    /// User's public key
    pub user_pubkey: Pubkey,
}

impl App {
    pub fn new(user_pubkey: Pubkey) -> Self {
        Self {
            screen: Screen::Loading {
                message: "Loading chats...".to_string(),
            },
            prev_screen: None,
            should_quit: false,
            input_mode: InputMode::Normal,
            input: String::new(),
            cursor_position: 0,
            accepted_chats: Vec::new(),
            pending_chats: Vec::new(),
            selected_chat: 0,
            messages: Vec::new(),
            message_scroll: 0,
            status: None,
            user_pubkey,
        }
    }

    /// Navigate to a new screen
    pub fn navigate_to(&mut self, screen: Screen) {
        self.prev_screen = Some(self.screen.clone());
        self.screen = screen;
        self.input.clear();
        self.cursor_position = 0;
        self.input_mode = InputMode::Normal;
    }

    /// Go back to previous screen
    pub fn go_back(&mut self) {
        if let Some(prev) = self.prev_screen.take() {
            self.screen = prev;
            self.input.clear();
            self.cursor_position = 0;
            self.input_mode = InputMode::Normal;
        } else {
            self.screen = Screen::ChatList;
        }
    }

    /// Get total number of chats
    pub fn total_chats(&self) -> usize {
        self.accepted_chats.len() + self.pending_chats.len()
    }

    /// Get currently selected chat
    pub fn get_selected_chat(&self) -> Option<&ChatThread> {
        if self.selected_chat < self.accepted_chats.len() {
            self.accepted_chats.get(self.selected_chat)
        } else {
            self.pending_chats
                .get(self.selected_chat - self.accepted_chats.len())
        }
    }

    /// Move selection up
    pub fn select_prev(&mut self) {
        if self.selected_chat > 0 {
            self.selected_chat -= 1;
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.selected_chat + 1 < self.total_chats() {
            self.selected_chat += 1;
        }
    }

    /// Scroll messages up
    pub fn scroll_up(&mut self) {
        if self.message_scroll > 0 {
            self.message_scroll -= 1;
        }
    }

    /// Scroll messages down
    pub fn scroll_down(&mut self) {
        if self.message_scroll + 1 < self.messages.len() {
            self.message_scroll += 1;
        }
    }

    /// Enter character in input
    pub fn enter_char(&mut self, c: char) {
        self.input.insert(self.cursor_position, c);
        self.cursor_position += 1;
    }

    /// Delete character before cursor
    pub fn delete_char(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
            self.input.remove(self.cursor_position);
        }
    }

    /// Move cursor left
    pub fn move_cursor_left(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    /// Move cursor right
    pub fn move_cursor_right(&mut self) {
        if self.cursor_position < self.input.len() {
            self.cursor_position += 1;
        }
    }

    /// Set status message
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = Some(msg.into());
    }

    /// Clear status message
    pub fn clear_status(&mut self) {
        self.status = None;
    }

    /// Update chats with resolved threads
    pub fn update_chats(&mut self, accepted: Vec<ChatThread>, pending: Vec<ChatThread>) {
        self.accepted_chats = accepted;
        self.pending_chats = pending;
    }

    /// Update messages from MsgV1 list
    pub fn update_messages(&mut self, msgs: Vec<MsgV1>, aes_key: &[u8; 32]) {
        self.messages = msgs
            .into_iter()
            .map(|msg| {
                let sender = Pubkey::from(msg.sender);
                let is_me = sender == self.user_pubkey;

                let content = Message::decrypt(aes_key, &msg.iv, &msg.ciphertext)
                    .map(|m| m.display_text().to_string())
                    .unwrap_or_else(|_| "<decryption failed>".to_string());

                let timestamp_str = chrono::DateTime::from_timestamp(msg.unix_timestamp, 0)
                    .map(|dt| dt.format("%H:%M").to_string())
                    .unwrap_or_else(|| "??:??".to_string());

                DisplayMessage {
                    sender,
                    is_me,
                    content,
                    timestamp: msg.unix_timestamp,
                    timestamp_str,
                }
            })
            .collect();

        // Scroll to bottom
        if !self.messages.is_empty() {
            self.message_scroll = self.messages.len().saturating_sub(1);
        }
    }
}
