//! Application state and screen management for the TUI.

use solana_sdk::pubkey::Pubkey;
use solcrypt_program::{ClientSideMessage, GroupMsgV1, MsgV1};

use crate::crypto::ClientSideMessageExt;

/// The type of thread (DM or Group)
#[derive(Debug, Clone, PartialEq)]
pub enum ThreadType {
    Dm,
    Group,
}

/// The current screen/view in the application
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    /// Chat list showing accepted and pending conversations
    ChatList,
    /// Active DM chat conversation view
    Chat { recipient: Pubkey },
    /// Active group chat view
    GroupChat { group_id: [u8; 32] },
    /// New chat dialog to enter recipient pubkey
    NewChat,
    /// New group dialog
    NewGroup,
    /// Invite member to group dialog
    InviteMember { group_id: [u8; 32] },
    /// Loading screen while performing async operations
    Loading { message: String },
    /// Error screen
    Error { message: String },
}

/// A DM chat thread with metadata for display
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

/// A group chat thread with metadata for display
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GroupThread {
    pub group_id: [u8; 32],
    /// Group name (for now, abbreviated group_id)
    pub name: String,
    pub is_accepted: bool,
    pub last_message: Option<String>,
    pub unread: bool,
    /// Number of members (if known)
    pub member_count: Option<usize>,
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

/// Which tab is selected in the chat list
#[derive(Debug, Clone, PartialEq)]
pub enum ListTab {
    Chats,
    Groups,
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

    /// Current tab in chat list
    pub list_tab: ListTab,

    /// Accepted DM chat threads
    pub accepted_chats: Vec<ChatThread>,
    /// Pending DM chat threads
    pub pending_chats: Vec<ChatThread>,
    /// Currently selected chat index (in combined list)
    pub selected_chat: usize,

    /// Accepted group threads
    pub accepted_groups: Vec<GroupThread>,
    /// Pending group invites
    pub pending_groups: Vec<GroupThread>,
    /// Currently selected group index (in combined list)
    pub selected_group: usize,

    /// Messages in current chat (DM)
    pub messages: Vec<DisplayMessage>,
    /// Messages in current group chat
    pub group_messages: Vec<DisplayMessage>,
    /// Scroll position in messages
    pub message_scroll: usize,

    /// Current group ID (when in group chat)
    pub current_group_id: Option<[u8; 32]>,
    /// Current group AES key (when in group chat)
    pub current_group_aes_key: Option<[u8; 32]>,

    /// Status message to show at bottom
    pub status: Option<String>,

    /// User's public key
    pub user_pubkey: Pubkey,

    /// Whether a message is currently being sent (for overlay popup)
    pub sending_message: bool,

    /// Whether messages are being refreshed (for overlay popup)
    pub refreshing: bool,
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
            list_tab: ListTab::Chats,
            accepted_chats: Vec::new(),
            pending_chats: Vec::new(),
            selected_chat: 0,
            accepted_groups: Vec::new(),
            pending_groups: Vec::new(),
            selected_group: 0,
            messages: Vec::new(),
            group_messages: Vec::new(),
            message_scroll: 0,
            current_group_id: None,
            current_group_aes_key: None,
            status: None,
            user_pubkey,
            sending_message: false,
            refreshing: false,
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

    /// Update DM chats with resolved threads
    pub fn update_chats(&mut self, accepted: Vec<ChatThread>, pending: Vec<ChatThread>) {
        self.accepted_chats = accepted;
        self.pending_chats = pending;
    }

    /// Update groups with resolved threads
    pub fn update_groups(&mut self, accepted: Vec<GroupThread>, pending: Vec<GroupThread>) {
        self.accepted_groups = accepted;
        self.pending_groups = pending;
    }

    /// Get total number of groups
    pub fn total_groups(&self) -> usize {
        self.accepted_groups.len() + self.pending_groups.len()
    }

    /// Get currently selected group
    pub fn get_selected_group(&self) -> Option<&GroupThread> {
        if self.selected_group < self.accepted_groups.len() {
            self.accepted_groups.get(self.selected_group)
        } else {
            self.pending_groups
                .get(self.selected_group - self.accepted_groups.len())
        }
    }

    /// Move group selection up
    pub fn select_prev_group(&mut self) {
        if self.selected_group > 0 {
            self.selected_group -= 1;
        }
    }

    /// Move group selection down
    pub fn select_next_group(&mut self) {
        if self.selected_group + 1 < self.total_groups() {
            self.selected_group += 1;
        }
    }

    /// Switch to the next tab
    pub fn next_tab(&mut self) {
        self.list_tab = match self.list_tab {
            ListTab::Chats => ListTab::Groups,
            ListTab::Groups => ListTab::Chats,
        };
    }

    /// Update messages from MsgV1 list
    pub fn update_messages(&mut self, msgs: Vec<MsgV1>, aes_key: &[u8; 32]) {
        self.messages = msgs
            .into_iter()
            .map(|msg| {
                let sender = Pubkey::from(msg.sender);
                let is_me = sender == self.user_pubkey;

                let content = ClientSideMessage::decrypt(aes_key, &msg.iv, &msg.ciphertext)
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

    /// Update group messages from GroupMsgV1 list
    pub fn update_group_messages(&mut self, msgs: Vec<GroupMsgV1>, aes_key: &[u8; 32]) {
        self.group_messages = msgs
            .into_iter()
            .map(|msg| {
                let sender = Pubkey::from(msg.sender);
                let is_me = sender == self.user_pubkey;

                let content = ClientSideMessage::decrypt(aes_key, &msg.iv, &msg.ciphertext)
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
        if !self.group_messages.is_empty() {
            self.message_scroll = self.group_messages.len().saturating_sub(1);
        }
    }

    /// Set current group context
    pub fn set_current_group(&mut self, group_id: [u8; 32], aes_key: [u8; 32]) {
        self.current_group_id = Some(group_id);
        self.current_group_aes_key = Some(aes_key);
    }

    /// Clear current group context
    pub fn clear_current_group(&mut self) {
        self.current_group_id = None;
        self.current_group_aes_key = None;
        self.group_messages.clear();
    }
}
