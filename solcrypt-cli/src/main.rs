//! Solcrypt CLI - End-to-End Encrypted Messaging on Solana
//!
//! An interactive TUI for the Solcrypt E2EE messaging protocol.

mod app;
mod client;
mod crypto;
mod events;
mod instructions;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use solana_sdk::{pubkey::Pubkey, signature::read_keypair_file};
use solcrypt_program::ClientSideMessage;
use x25519_dalek::PublicKey as X25519PublicKey;

use app::{App, Screen};
use client::SolcryptClient;
use crypto::{
    compute_thread_id, decrypt_group_key, derive_aes_key, derive_x25519_keypair,
    encrypt_group_key_for_member, generate_group_aes_key, random_group_id, ClientSideMessageExt,
};
use events::{handle_key_event, poll_event, EventResult};
use instructions::{
    create_accept_group_invite_transaction, create_accept_thread_transaction,
    create_create_group_transaction, create_init_user_transaction,
    create_invite_to_group_transaction, create_send_dm_message_transaction,
    create_send_group_message_transaction,
};

/// Solcrypt CLI - End-to-End Encrypted Messaging on Solana
#[derive(Parser)]
#[command(name = "solcrypt-cli")]
#[command(about = "End-to-End Encrypted Messaging on Solana using ZK Compression")]
#[command(version)]
struct Cli {
    /// Path to the Solana keypair JSON file
    #[arg(short, long)]
    keypair: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let cli = Cli::parse();

    // Load the keypair
    let keypair = read_keypair_file(&cli.keypair)
        .map_err(|e| anyhow::anyhow!("Failed to read keypair file: {}", e))?;

    // Derive X25519 keypair for E2EE
    let (x25519_secret, x25519_public) = derive_x25519_keypair(&keypair);

    // Create the client
    let mut client = SolcryptClient::new(keypair).await?;

    // Ensure user is initialized
    ensure_initialized(&mut client, x25519_public).await?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new(client.pubkey());

    // Run the app
    let result = run_app(&mut terminal, &mut app, &mut client, &x25519_secret).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    // Handle errors
    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
    }

    Ok(())
}

/// Main application loop
async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
) -> Result<()> {
    // Initial load of chats
    load_chats(app, client).await?;
    app.screen = Screen::ChatList;

    loop {
        // Draw UI
        terminal.draw(|f| ui::render(f, app))?;

        // Poll for events
        if let Some(event) = poll_event(Duration::from_millis(100))? {
            if let Event::Key(key) = event {
                let result = handle_key_event(app, key);

                match result {
                    EventResult::Continue => {}
                    EventResult::RefreshChats => {
                        app.screen = Screen::Loading {
                            message: "Refreshing...".to_string(),
                        };
                        terminal.draw(|f| ui::render(f, app))?;
                        load_chats(app, client).await?;
                        app.screen = Screen::ChatList;
                    }
                    EventResult::OpenChat => {
                        if let Some(chat) = app.get_selected_chat() {
                            let recipient = chat.other_party;
                            app.navigate_to(Screen::Chat { recipient });
                            load_messages(app, client, x25519_secret, &recipient).await?;
                        }
                    }
                    EventResult::SendMessage(content) => {
                        if let Screen::Chat { recipient } = &app.screen {
                            let recipient = *recipient;

                            // Show sending popup
                            app.sending_message = true;
                            terminal.draw(|f| ui::render(f, app))?;

                            // Send message
                            let result =
                                send_message(app, client, x25519_secret, &recipient, &content)
                                    .await;

                            // Hide sending popup
                            app.sending_message = false;

                            if let Err(e) = result {
                                app.set_status(format!("Failed to send: {:#}", e));
                            } else {
                                // Reload messages
                                load_messages(app, client, x25519_secret, &recipient).await?;
                            }
                        }
                    }
                    EventResult::StartNewChat(recipient_str) => {
                        match recipient_str.parse::<Pubkey>() {
                            Ok(recipient) => {
                                // Check if recipient is initialized
                                match client.get_user_x25519_pubkey(&recipient).await {
                                    Ok(Some(_)) => {
                                        app.navigate_to(Screen::Chat { recipient });
                                        load_messages(app, client, x25519_secret, &recipient)
                                            .await?;
                                    }
                                    Ok(None) => {
                                        app.navigate_to(Screen::Error {
                                            message: "Recipient has not initialized their account"
                                                .to_string(),
                                        });
                                    }
                                    Err(e) => {
                                        app.navigate_to(Screen::Error {
                                            message: format!("Failed to check recipient: {:#}", e),
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                app.navigate_to(Screen::Error {
                                    message: "Invalid public key format".to_string(),
                                });
                            }
                        }
                    }
                    EventResult::AcceptChat => {
                        if let Some(chat) = app.get_selected_chat() {
                            if !chat.is_accepted {
                                let thread_id = chat.thread_id;
                                app.screen = Screen::Loading {
                                    message: "Accepting chat...".to_string(),
                                };
                                terminal.draw(|f| ui::render(f, app))?;

                                match accept_chat(client, thread_id).await {
                                    Ok(_) => {
                                        load_chats(app, client).await?;
                                        app.screen = Screen::ChatList;
                                        app.set_status("Chat accepted!");
                                    }
                                    Err(e) => {
                                        app.screen = Screen::Error {
                                            message: format!("Failed to accept: {:#}", e),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    EventResult::LoadMessages => {
                        if let Screen::Chat { recipient } = &app.screen {
                            let recipient = *recipient;

                            // Show refreshing popup
                            app.refreshing = true;
                            terminal.draw(|f| ui::render(f, app))?;

                            load_messages(app, client, x25519_secret, &recipient).await?;

                            // Hide refreshing popup
                            app.refreshing = false;
                        }
                    }
                    // Group chat handlers
                    EventResult::OpenGroup => {
                        if let Some(group) = app.get_selected_group() {
                            let group_id = group.group_id;
                            app.navigate_to(Screen::GroupChat { group_id });
                            load_group_messages(app, client, x25519_secret, &group_id).await?;
                        }
                    }
                    EventResult::SendGroupMessage(content) => {
                        if let Screen::GroupChat { group_id } = &app.screen {
                            let group_id = *group_id;

                            // Show sending popup
                            app.sending_message = true;
                            terminal.draw(|f| ui::render(f, app))?;

                            let result =
                                send_group_message(app, client, x25519_secret, &group_id, &content)
                                    .await;

                            // Hide sending popup
                            app.sending_message = false;

                            if let Err(e) = result {
                                app.set_status(format!("Failed to send: {:#}", e));
                            } else {
                                // Reload messages
                                load_group_messages(app, client, x25519_secret, &group_id).await?;
                            }
                        }
                    }
                    EventResult::CreateGroup => {
                        app.screen = Screen::Loading {
                            message: "Creating group...".to_string(),
                        };
                        terminal.draw(|f| ui::render(f, app))?;

                        match create_group(client, x25519_secret).await {
                            Ok(group_id) => {
                                load_chats(app, client).await?;
                                app.screen = Screen::ChatList;
                                app.set_status(format!(
                                    "Group created! ID: {}",
                                    hex::encode(&group_id[..4])
                                ));
                            }
                            Err(e) => {
                                app.screen = Screen::Error {
                                    message: format!("Failed to create group: {:#}", e),
                                };
                            }
                        }
                    }
                    EventResult::AcceptGroupInvite => {
                        if let Some(group) = app.get_selected_group() {
                            if !group.is_accepted {
                                let group_id = group.group_id;
                                app.screen = Screen::Loading {
                                    message: "Accepting group invite...".to_string(),
                                };
                                terminal.draw(|f| ui::render(f, app))?;

                                match accept_group_invite(client, group_id).await {
                                    Ok(_) => {
                                        load_chats(app, client).await?;
                                        app.screen = Screen::ChatList;
                                        app.set_status("Group invite accepted!");
                                    }
                                    Err(e) => {
                                        app.screen = Screen::Error {
                                            message: format!("Failed to accept: {:#}", e),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    EventResult::LoadGroupMessages => {
                        if let Screen::GroupChat { group_id } = &app.screen {
                            let group_id = *group_id;

                            // Show refreshing popup
                            app.refreshing = true;
                            terminal.draw(|f| ui::render(f, app))?;

                            load_group_messages(app, client, x25519_secret, &group_id).await?;

                            // Hide refreshing popup
                            app.refreshing = false;
                        }
                    }
                    EventResult::InviteMember(invitee_str) => {
                        // Get the group_id from prev_screen (we navigated from GroupChat)
                        let group_id =
                            if let Some(Screen::GroupChat { group_id }) = &app.prev_screen {
                                *group_id
                            } else if let Screen::InviteMember { group_id } = &app.screen {
                                *group_id
                            } else {
                                app.navigate_to(Screen::Error {
                                    message: "No group context".to_string(),
                                });
                                continue;
                            };

                        match invitee_str.parse::<Pubkey>() {
                            Ok(invitee) => {
                                app.screen = Screen::Loading {
                                    message: "Inviting member...".to_string(),
                                };
                                terminal.draw(|f| ui::render(f, app))?;

                                match invite_member(client, x25519_secret, &group_id, &invitee)
                                    .await
                                {
                                    Ok(_) => {
                                        app.navigate_to(Screen::GroupChat { group_id });
                                        load_group_messages(app, client, x25519_secret, &group_id)
                                            .await?;
                                        app.set_status("Member invited successfully!");
                                    }
                                    Err(e) => {
                                        app.navigate_to(Screen::Error {
                                            message: format!("Failed to invite: {:#}", e),
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                app.navigate_to(Screen::Error {
                                    message: "Invalid public key format".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Ensure the user account is initialized
async fn ensure_initialized(
    client: &mut SolcryptClient,
    x25519_public: X25519PublicKey,
) -> Result<()> {
    let exists = client.user_account_exists(&client.pubkey()).await?;

    if !exists {
        eprintln!("Initializing user account...");
        let tx = create_init_user_transaction(client, x25519_public.to_bytes()).await?;
        client.send_and_confirm_transaction(tx).await?;
        eprintln!("User account initialized!");
    }

    Ok(())
}

/// Load chats and groups into app state
async fn load_chats(app: &mut App, client: &mut SolcryptClient) -> Result<()> {
    use crate::app::{ChatThread, GroupThread};
    use crate::client::format_group_id;

    let my_pubkey = client.pubkey();

    // Load DM threads
    let (dm_accepted, dm_pending) = client.get_dm_threads().await.unwrap_or_default();

    let mut accepted_chats = Vec::new();
    let mut pending_chats = Vec::new();

    // Resolve other_party for each accepted DM thread
    for entry in dm_accepted {
        if let Ok(Some(other_party)) = client
            .get_other_party_for_thread(entry.thread_id, &my_pubkey)
            .await
        {
            accepted_chats.push(ChatThread {
                thread_id: entry.thread_id,
                other_party,
                is_accepted: true,
                last_message: None,
                unread: false,
            });
        }
    }

    // Resolve other_party for each pending DM thread
    for entry in dm_pending {
        if let Ok(Some(other_party)) = client
            .get_other_party_for_thread(entry.thread_id, &my_pubkey)
            .await
        {
            pending_chats.push(ChatThread {
                thread_id: entry.thread_id,
                other_party,
                is_accepted: false,
                last_message: None,
                unread: true,
            });
        }
    }

    app.update_chats(accepted_chats, pending_chats);

    // Load group threads
    let (group_accepted, group_pending) = client.get_group_threads().await.unwrap_or_default();

    let mut accepted_groups = Vec::new();
    let mut pending_groups = Vec::new();

    for entry in group_accepted {
        accepted_groups.push(GroupThread {
            group_id: entry.thread_id,
            name: format_group_id(&entry.thread_id),
            is_accepted: true,
            last_message: None,
            unread: false,
            member_count: None,
        });
    }

    for entry in group_pending {
        pending_groups.push(GroupThread {
            group_id: entry.thread_id,
            name: format_group_id(&entry.thread_id),
            is_accepted: false,
            last_message: None,
            unread: true,
            member_count: None,
        });
    }

    app.update_groups(accepted_groups, pending_groups);

    Ok(())
}

/// Load messages for a chat
async fn load_messages(
    app: &mut App,
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    recipient: &Pubkey,
) -> Result<()> {
    // Get recipient's X25519 pubkey
    let recipient_x25519_bytes = client
        .get_user_x25519_pubkey(recipient)
        .await?
        .context("Recipient not initialized")?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    // Derive AES key
    let aes_key = derive_aes_key(x25519_secret, &recipient_x25519);

    // Compute thread ID
    let thread_id = compute_thread_id(&client.pubkey(), recipient);

    // Fetch messages
    let messages = client.get_messages_for_thread(thread_id).await?;

    app.update_messages(messages, &aes_key);
    Ok(())
}

/// Send a message
async fn send_message(
    _app: &mut App,
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    recipient: &Pubkey,
    content: &str,
) -> Result<()> {
    // Get recipient's X25519 pubkey
    let recipient_x25519_bytes = client
        .get_user_x25519_pubkey(recipient)
        .await?
        .context("Recipient not initialized")?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    // Derive AES key
    let aes_key = derive_aes_key(x25519_secret, &recipient_x25519);

    // Compute thread ID
    let thread_id = compute_thread_id(&client.pubkey(), recipient);

    // Encrypt message
    let message = ClientSideMessage::Text(content.to_string());
    let (iv, ciphertext) = message.encrypt(&aes_key)?;

    // Send transaction
    let tx =
        create_send_dm_message_transaction(client, recipient, thread_id, iv, ciphertext).await?;
    client.send_and_confirm_transaction(tx).await?;

    Ok(())
}

/// Accept a pending chat
async fn accept_chat(client: &mut SolcryptClient, thread_id: [u8; 32]) -> Result<()> {
    let tx = create_accept_thread_transaction(client, thread_id).await?;
    client.send_and_confirm_transaction(tx).await?;
    Ok(())
}

// ============================================================================
// Group Chat Functions
// ============================================================================

/// Create a new group
async fn create_group(
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
) -> Result<[u8; 32]> {
    // Generate random group ID and AES key
    let group_id = random_group_id();
    let aes_key = generate_group_aes_key();

    // Encrypt the AES key for ourselves
    let x25519_public = X25519PublicKey::from(x25519_secret);
    let encrypted_aes_key = encrypt_group_key_for_member(&aes_key, x25519_secret, &x25519_public);

    // Create the group
    let tx = create_create_group_transaction(client, group_id, encrypted_aes_key).await?;
    client.send_and_confirm_transaction(tx).await?;

    Ok(group_id)
}

/// Accept a pending group invite
async fn accept_group_invite(client: &mut SolcryptClient, group_id: [u8; 32]) -> Result<()> {
    let tx = create_accept_group_invite_transaction(client, group_id).await?;
    client.send_and_confirm_transaction(tx).await?;
    Ok(())
}

/// Invite a member to a group
async fn invite_member(
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    group_id: &[u8; 32],
    invitee: &Pubkey,
) -> Result<()> {
    // Get the group account to find the owner
    let group_account = client
        .get_group_account(group_id)
        .await?
        .context("Group not found")?;

    // Get the group AES key (we need to decrypt it first)
    let (my_key, _) = client
        .get_my_group_key(group_id)
        .await?
        .context("You are not a member of this group")?;

    // Get owner's X25519 pubkey to decrypt the group key
    let owner_x25519_bytes = client
        .get_user_x25519_pubkey(&Pubkey::from(group_account.owner))
        .await?
        .context("Group owner not initialized")?;
    let owner_x25519 = X25519PublicKey::from(owner_x25519_bytes);

    // Decrypt the group AES key
    let group_aes_key = decrypt_group_key(&my_key.encrypted_aes_key, x25519_secret, &owner_x25519)?;

    // Get invitee's X25519 pubkey
    let invitee_x25519_bytes = client
        .get_user_x25519_pubkey(invitee)
        .await?
        .context("Invitee has not initialized their account")?;
    let invitee_x25519 = X25519PublicKey::from(invitee_x25519_bytes);

    // Encrypt the group AES key for the invitee
    let invitee_encrypted_key =
        encrypt_group_key_for_member(&group_aes_key, x25519_secret, &invitee_x25519);

    // Send the invite transaction
    let tx = create_invite_to_group_transaction(client, *group_id, invitee, invitee_encrypted_key)
        .await?;
    client.send_and_confirm_transaction(tx).await?;

    Ok(())
}

/// Load group messages
async fn load_group_messages(
    app: &mut App,
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    group_id: &[u8; 32],
) -> Result<()> {
    // Get the group account to find the owner's pubkey
    let group_account = client
        .get_group_account(group_id)
        .await?
        .context("Group not found")?;

    // Get my GroupKeyV1 to get the encrypted AES key
    let (group_key, _) = client
        .get_my_group_key(group_id)
        .await?
        .context("You are not a member of this group")?;

    // Get the group owner's X25519 pubkey to derive the decryption key
    let owner_x25519_bytes = client
        .get_user_x25519_pubkey(&Pubkey::from(group_account.owner))
        .await?
        .context("Group owner not initialized")?;
    let owner_x25519 = X25519PublicKey::from(owner_x25519_bytes);

    // Decrypt the AES key
    let aes_key = decrypt_group_key(&group_key.encrypted_aes_key, x25519_secret, &owner_x25519)?;

    // Store the group context
    app.set_current_group(*group_id, aes_key);

    // Fetch and decrypt messages
    let messages = client.get_group_messages(group_id).await?;
    app.update_group_messages(messages, &aes_key);

    Ok(())
}

/// Send a group message
async fn send_group_message(
    app: &mut App,
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    group_id: &[u8; 32],
    content: &str,
) -> Result<()> {
    // Get the cached AES key, or load it if not cached
    let aes_key = match app.current_group_aes_key {
        Some(key) => key,
        None => {
            // Get the group account to find the owner's pubkey
            let group_account = client
                .get_group_account(group_id)
                .await?
                .context("Group not found")?;

            // Get my GroupKeyV1 to get the encrypted AES key
            let (group_key, _) = client
                .get_my_group_key(group_id)
                .await?
                .context("You are not a member of this group")?;

            // Get the group owner's X25519 pubkey
            let owner_x25519_bytes = client
                .get_user_x25519_pubkey(&Pubkey::from(group_account.owner))
                .await?
                .context("Group owner not initialized")?;
            let owner_x25519 = X25519PublicKey::from(owner_x25519_bytes);

            // Decrypt the AES key
            decrypt_group_key(&group_key.encrypted_aes_key, x25519_secret, &owner_x25519)?
        }
    };

    // Get my GroupKeyV1 for the transaction
    let (group_key, _) = client
        .get_my_group_key(group_id)
        .await?
        .context("You are not a member of this group")?;

    // Encrypt the message
    let message = ClientSideMessage::Text(content.to_string());
    let (iv, ciphertext) = message.encrypt(&aes_key)?;

    // Send transaction
    let tx = create_send_group_message_transaction(
        client,
        *group_id,
        group_key.key_version,
        group_key.role,
        group_key.encrypted_aes_key,
        iv,
        ciphertext,
    )
    .await?;
    client.send_and_confirm_transaction(tx).await?;

    Ok(())
}
