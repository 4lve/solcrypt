//! Event handling for keyboard input.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;

use crate::app::{App, InputMode, ListTab, Screen};

/// Result type for event handling
pub enum EventResult {
    /// Continue normally
    Continue,
    /// Refresh chats
    RefreshChats,
    /// Open selected chat
    OpenChat,
    /// Open selected group
    OpenGroup,
    /// Send message with content
    SendMessage(String),
    /// Send group message with content
    SendGroupMessage(String),
    /// Start new chat with recipient
    StartNewChat(String),
    /// Create new group
    CreateGroup,
    /// Accept pending chat
    AcceptChat,
    /// Accept pending group invite
    AcceptGroupInvite,
    /// Load messages for current chat
    LoadMessages,
    /// Load messages for current group
    LoadGroupMessages,
    /// Invite member to current group
    InviteMember(String),
    /// Remove member from group (admin action) - takes pubkey
    RemoveMember(Pubkey),
    /// Leave group voluntarily
    LeaveGroup,
    /// Set member role (owner action) - takes pubkey and new role
    SetMemberRole(Pubkey, u8),
    /// Rotate group key (owner action)
    RotateGroupKey,
    /// Load members for remove screen
    LoadMembersForRemove([u8; 32]),
    /// Load members for role change screen
    LoadMembersForRole([u8; 32]),
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
        Screen::GroupChat { .. } => handle_group_chat_keys(app, key),
        Screen::NewChat => handle_new_chat_keys(app, key),
        Screen::NewGroup => handle_new_group_keys(app, key),
        Screen::InviteMember { .. } => handle_invite_member_keys(app, key),
        Screen::RemoveMember { .. } => handle_remove_member_keys(app, key),
        Screen::SetMemberRole { .. } => handle_set_member_role_keys(app, key),
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
        KeyCode::Tab => {
            app.next_tab();
            EventResult::Continue
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match app.list_tab {
                ListTab::Chats => app.select_prev(),
                ListTab::Groups => app.select_prev_group(),
            }
            EventResult::Continue
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match app.list_tab {
                ListTab::Chats => app.select_next(),
                ListTab::Groups => app.select_next_group(),
            }
            EventResult::Continue
        }
        KeyCode::Enter => match app.list_tab {
            ListTab::Chats => {
                if app.total_chats() > 0 {
                    EventResult::OpenChat
                } else {
                    EventResult::Continue
                }
            }
            ListTab::Groups => {
                if app.total_groups() > 0 {
                    EventResult::OpenGroup
                } else {
                    EventResult::Continue
                }
            }
        },
        KeyCode::Char('n') => {
            match app.list_tab {
                ListTab::Chats => {
                    app.navigate_to(Screen::NewChat);
                    app.input_mode = InputMode::Editing;
                }
                ListTab::Groups => {
                    app.navigate_to(Screen::NewGroup);
                    app.input_mode = InputMode::Editing;
                }
            }
            EventResult::Continue
        }
        KeyCode::Char('r') => EventResult::RefreshChats,
        KeyCode::Char('a') => {
            // Accept pending chat or group
            match app.list_tab {
                ListTab::Chats => {
                    if let Some(chat) = app.get_selected_chat() {
                        if !chat.is_accepted {
                            return EventResult::AcceptChat;
                        }
                    }
                }
                ListTab::Groups => {
                    if let Some(group) = app.get_selected_group() {
                        if !group.is_accepted {
                            return EventResult::AcceptGroupInvite;
                        }
                    }
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

/// Handle keys in group chat view
fn handle_group_chat_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match app.input_mode {
        InputMode::Normal => match key.code {
            KeyCode::Char('q') => {
                app.should_quit = true;
                EventResult::Continue
            }
            KeyCode::Esc => {
                app.clear_current_group();
                app.navigate_to(Screen::ChatList);
                EventResult::RefreshChats
            }
            KeyCode::Char('i') => {
                app.input_mode = InputMode::Editing;
                EventResult::Continue
            }
            KeyCode::Char('a') => {
                // Open invite member dialog
                if let Screen::GroupChat { group_id } = app.screen {
                    app.navigate_to(Screen::InviteMember { group_id });
                    app.input_mode = InputMode::Editing;
                }
                EventResult::Continue
            }
            KeyCode::Char('l') => {
                // Leave group
                EventResult::LeaveGroup
            }
            KeyCode::Char('x') => {
                // Remove member - needs to load members first
                if let Screen::GroupChat { group_id } = app.screen {
                    return EventResult::LoadMembersForRemove(group_id);
                }
                EventResult::Continue
            }
            KeyCode::Char('p') => {
                // Promote/demote - needs to load members first
                if let Screen::GroupChat { group_id } = app.screen {
                    return EventResult::LoadMembersForRole(group_id);
                }
                EventResult::Continue
            }
            KeyCode::Char('k') => {
                // Rotate group key (owner only)
                EventResult::RotateGroupKey
            }
            KeyCode::Char('r') => EventResult::LoadGroupMessages,
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
                    EventResult::SendGroupMessage(message)
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

/// Handle keys in new group dialog
fn handle_new_group_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.go_back();
            EventResult::Continue
        }
        KeyCode::Enter => {
            // Create group doesn't need input, just press enter
            app.input.clear();
            app.cursor_position = 0;
            EventResult::CreateGroup
        }
        _ => EventResult::Continue,
    }
}

/// Handle keys in invite member dialog
fn handle_invite_member_keys(app: &mut App, key: KeyEvent) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            app.go_back();
            EventResult::Continue
        }
        KeyCode::Enter => {
            if !app.input.is_empty() {
                let invitee_pubkey = app.input.clone();
                app.input.clear();
                app.cursor_position = 0;
                EventResult::InviteMember(invitee_pubkey)
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

/// Handle keys in remove member dialog (with member list)
fn handle_remove_member_keys(app: &mut App, key: KeyEvent) -> EventResult {
    if let Screen::RemoveMember {
        group_id: _,
        members,
        selected,
    } = &mut app.screen
    {
        match key.code {
            KeyCode::Esc => {
                app.go_back();
                EventResult::Continue
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if *selected > 0 {
                    *selected -= 1;
                }
                EventResult::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if *selected < members.len().saturating_sub(1) {
                    *selected += 1;
                }
                EventResult::Continue
            }
            KeyCode::Enter => {
                if let Some(member) = members.get(*selected) {
                    return EventResult::RemoveMember(member.pubkey);
                }
                EventResult::Continue
            }
            _ => EventResult::Continue,
        }
    } else {
        EventResult::Continue
    }
}

/// Handle keys in set member role dialog (with member list)
/// 'm' = set to member, 'a' = set to admin
fn handle_set_member_role_keys(app: &mut App, key: KeyEvent) -> EventResult {
    if let Screen::SetMemberRole {
        group_id: _,
        members,
        selected,
    } = &mut app.screen
    {
        match key.code {
            KeyCode::Esc => {
                app.go_back();
                EventResult::Continue
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if *selected > 0 {
                    *selected -= 1;
                }
                EventResult::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if *selected < members.len().saturating_sub(1) {
                    *selected += 1;
                }
                EventResult::Continue
            }
            KeyCode::Char('m') => {
                // Set to member (role 0)
                if let Some(member) = members.get(*selected) {
                    return EventResult::SetMemberRole(member.pubkey, 0);
                }
                EventResult::Continue
            }
            KeyCode::Char('a') => {
                // Set to admin (role 1)
                if let Some(member) = members.get(*selected) {
                    return EventResult::SetMemberRole(member.pubkey, 1);
                }
                EventResult::Continue
            }
            _ => EventResult::Continue,
        }
    } else {
        EventResult::Continue
    }
}
