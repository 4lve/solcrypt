//! Solcrypt CLI - End-to-End Encrypted Messaging on Solana
//!
//! A command-line interface for the Solcrypt E2EE messaging protocol.

mod client;
mod crypto;
mod instructions;

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use solana_sdk::{pubkey::Pubkey, signature::read_keypair_file};
use x25519_dalek::PublicKey as X25519PublicKey;

use client::{format_pubkey, format_thread_id, SolcryptClient};
use crypto::{compute_thread_id, derive_aes_key, derive_x25519_keypair, Message};
use instructions::{
    create_accept_thread_transaction, create_init_user_transaction,
    create_send_dm_message_transaction,
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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize your user account (auto-runs if needed for other commands)
    Init,

    /// List all your chats (accepted and pending)
    Chats,

    /// Load and display messages for a conversation
    Messages {
        /// The recipient's public key (base58)
        recipient: String,
    },

    /// Send an encrypted message to a recipient
    Send {
        /// The recipient's public key (base58)
        recipient: String,

        /// The message content to send
        message: String,
    },

    /// Accept a pending chat request
    Accept {
        /// The sender's public key (base58) whose chat request you want to accept
        sender: String,
    },

    /// Show your public key and X25519 public key
    Whoami,
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

    match cli.command {
        Commands::Init => {
            handle_init(&mut client, x25519_public).await?;
        }
        Commands::Chats => {
            ensure_initialized(&mut client, x25519_public).await?;
            handle_chats(&mut client).await?;
        }
        Commands::Messages { recipient } => {
            ensure_initialized(&mut client, x25519_public).await?;
            let recipient_pubkey = parse_pubkey(&recipient)?;
            handle_messages(&mut client, &x25519_secret, &recipient_pubkey).await?;
        }
        Commands::Send { recipient, message } => {
            ensure_initialized(&mut client, x25519_public).await?;
            let recipient_pubkey = parse_pubkey(&recipient)?;
            handle_send(&mut client, &x25519_secret, &recipient_pubkey, &message).await?;
        }
        Commands::Accept { sender } => {
            ensure_initialized(&mut client, x25519_public).await?;
            let sender_pubkey = parse_pubkey(&sender)?;
            handle_accept(&mut client, &sender_pubkey).await?;
        }
        Commands::Whoami => {
            handle_whoami(&client, &x25519_public)?;
        }
    }

    Ok(())
}

/// Parse a base58 public key string
fn parse_pubkey(s: &str) -> Result<Pubkey> {
    s.parse::<Pubkey>()
        .with_context(|| format!("Invalid public key: {}", s))
}

/// Ensure the user account is initialized, creating it if necessary
async fn ensure_initialized(
    client: &mut SolcryptClient,
    x25519_public: X25519PublicKey,
) -> Result<()> {
    let exists = client.user_account_exists(&client.pubkey()).await?;

    if !exists {
        println!("User account not found. Initializing...");
        let tx = create_init_user_transaction(client, x25519_public.to_bytes()).await?;
        let sig = client.send_and_confirm_transaction(tx).await?;
        println!("✓ User account initialized! Tx: {}", sig);
    }

    Ok(())
}

/// Handle the `init` command
async fn handle_init(client: &mut SolcryptClient, x25519_public: X25519PublicKey) -> Result<()> {
    let exists = client.user_account_exists(&client.pubkey()).await?;

    if exists {
        println!("User account already initialized.");
        return Ok(());
    }

    println!("Initializing user account...");
    let tx = create_init_user_transaction(client, x25519_public.to_bytes()).await?;
    let sig = client.send_and_confirm_transaction(tx).await?;
    println!("✓ User account initialized!");
    println!("  Transaction: {}", sig);
    println!("  Solana Pubkey: {}", client.pubkey());
    println!(
        "  X25519 Pubkey: {}",
        bs58::encode(x25519_public.as_bytes()).into_string()
    );

    Ok(())
}

/// Handle the `chats` command
async fn handle_chats(client: &mut SolcryptClient) -> Result<()> {
    let (accepted, pending) = client.get_threads().await?;

    if accepted.is_empty() && pending.is_empty() {
        println!("No chats found. Start a conversation with `send <recipient> <message>`");
        return Ok(());
    }

    if !accepted.is_empty() {
        println!("\n=== Accepted Chats ({}) ===", accepted.len());
        for thread in &accepted {
            println!("  Thread: {}", format_thread_id(&thread.thread_id));
        }
    }

    if !pending.is_empty() {
        println!("\n=== Pending Requests ({}) ===", pending.len());
        println!("(Use `accept <sender>` to accept a chat request)");
        for thread in &pending {
            println!("  Thread: {}", format_thread_id(&thread.thread_id));
        }
    }

    println!();
    Ok(())
}

/// Handle the `messages` command
async fn handle_messages(
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    recipient: &Pubkey,
) -> Result<()> {
    // Get recipient's X25519 public key for decryption
    let recipient_x25519_bytes = client
        .get_user_x25519_pubkey(recipient)
        .await?
        .context("Recipient has not initialized their account")?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    // Derive the shared AES key
    let aes_key = derive_aes_key(x25519_secret, &recipient_x25519);

    // Compute thread ID
    let thread_id = compute_thread_id(&client.pubkey(), recipient);

    println!("Loading messages with {}...", format_pubkey(recipient));
    println!("Thread ID: {}", format_thread_id(&thread_id));
    println!();

    // Fetch messages
    let messages = client.get_messages_for_thread(thread_id).await?;

    if messages.is_empty() {
        println!("No messages in this conversation yet.");
        return Ok(());
    }

    println!("=== Messages ({}) ===\n", messages.len());

    for msg in messages {
        // Determine if this is from us or them
        let sender_pubkey = Pubkey::from(msg.sender);
        let is_me = sender_pubkey == client.pubkey();
        let sender_label = if is_me {
            "You"
        } else {
            &format_pubkey(&sender_pubkey)
        };

        // Format timestamp
        let timestamp = Utc
            .timestamp_opt(msg.unix_timestamp, 0)
            .single()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown time".to_string());

        // Decrypt message content
        match Message::decrypt(&aes_key, &msg.iv, &msg.ciphertext) {
            Ok(decrypted) => {
                println!(
                    "[{}] {}: {}",
                    timestamp,
                    sender_label,
                    decrypted.display_text()
                );
            }
            Err(_) => {
                println!("[{}] {}: <decryption failed>", timestamp, sender_label);
            }
        }
    }

    println!();
    Ok(())
}

/// Handle the `send` command
async fn handle_send(
    client: &mut SolcryptClient,
    x25519_secret: &x25519_dalek::StaticSecret,
    recipient: &Pubkey,
    message_text: &str,
) -> Result<()> {
    // Check recipient is initialized
    let recipient_x25519_bytes = client
        .get_user_x25519_pubkey(recipient)
        .await?
        .context("Recipient has not initialized their account. They need to run `init` first.")?;
    let recipient_x25519 = X25519PublicKey::from(recipient_x25519_bytes);

    // Derive the shared AES key
    let aes_key = derive_aes_key(x25519_secret, &recipient_x25519);

    // Compute thread ID
    let thread_id = compute_thread_id(&client.pubkey(), recipient);

    // Create and encrypt the message
    let message = Message::text(message_text);
    let (iv, ciphertext) = message.encrypt(&aes_key)?;

    println!("Sending message to {}...", format_pubkey(recipient));

    // Build and send transaction
    let tx =
        create_send_dm_message_transaction(client, recipient, thread_id, iv, ciphertext).await?;
    println!("Transaction");
    let sig = client.send_and_confirm_transaction(tx).await?;

    println!("✓ Message sent!");
    println!("  Transaction: {}", sig);

    Ok(())
}

/// Handle the `accept` command
async fn handle_accept(client: &mut SolcryptClient, sender: &Pubkey) -> Result<()> {
    // Compute thread ID
    let thread_id = compute_thread_id(&client.pubkey(), sender);

    println!("Accepting chat request from {}...", format_pubkey(sender));

    let tx = create_accept_thread_transaction(client, thread_id).await?;
    let sig = client.send_and_confirm_transaction(tx).await?;

    println!("✓ Chat request accepted!");
    println!("  Transaction: {}", sig);

    Ok(())
}

/// Handle the `whoami` command
fn handle_whoami(client: &SolcryptClient, x25519_public: &X25519PublicKey) -> Result<()> {
    println!("=== Your Identity ===");
    println!("Solana Pubkey: {}", client.pubkey());
    println!(
        "X25519 Pubkey: {}",
        bs58::encode(x25519_public.as_bytes()).into_string()
    );
    println!("\nShare your Solana Pubkey with others so they can message you.");

    Ok(())
}
