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
use crypto::{compute_thread_id, derive_aes_key, derive_x25519_keypair};
use events::{handle_key_event, poll_event, EventResult};
use instructions::{
    create_accept_thread_transaction, create_init_user_transaction,
    create_send_dm_message_transaction,
};

use crate::crypto::ClientSideMessageExt;

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
                            if !chat.is_accepted {
                                app.set_status("Accept this chat first with 'a'");
                            } else {
                                let recipient = chat.other_party;
                                app.navigate_to(Screen::Chat { recipient });
                                load_messages(app, client, x25519_secret, &recipient).await?;
                            }
                        }
                    }
                    EventResult::SendMessage(content) => {
                        if let Screen::Chat { recipient } = &app.screen {
                            let recipient = *recipient;
                            send_message(app, client, x25519_secret, &recipient, &content).await?;
                            // Reload messages
                            load_messages(app, client, x25519_secret, &recipient).await?;
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
                                            message: format!("Failed to check recipient: {}", e),
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
                                            message: format!("Failed to accept: {}", e),
                                        };
                                    }
                                }
                            }
                        }
                    }
                    EventResult::LoadMessages => {
                        if let Screen::Chat { recipient } = &app.screen {
                            let recipient = *recipient;
                            load_messages(app, client, x25519_secret, &recipient).await?;
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

/// Load chats into app state
async fn load_chats(app: &mut App, client: &mut SolcryptClient) -> Result<()> {
    use crate::app::ChatThread;

    let (accepted_entries, pending_entries) = client.get_threads().await.unwrap_or_default();
    let my_pubkey = client.pubkey();

    let mut accepted_chats = Vec::new();
    let mut pending_chats = Vec::new();

    // Resolve other_party for each accepted thread
    for entry in accepted_entries {
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

    // Resolve other_party for each pending thread
    for entry in pending_entries {
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
