//! RPC client wrapper for Solcrypt operations.
//!
//! Provides functionality for:
//! - Connecting to the Helius devnet RPC
//! - Fetching UserAccount PDAs
//! - Querying compressed message accounts

use anyhow::{Context, Result};
use borsh::BorshDeserialize;
use light_client::{
    indexer::{AddressWithTree, Indexer, ValidityProofWithContext},
    rpc::{LightClient, LightClientConfig, Rpc},
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::Transaction,
};
use solcrypt_program::{MsgV1, ThreadEntry, UserAccount, THREAD_STATE_ACCEPTED, USER_SEED};

/// Default RPC URL for Helius devnet
//pub const RPC_URL: &str = "https://xenia-573pc0-fast-devnet.helius-rpc.com";

/// Client for interacting with the Solcrypt program
pub struct SolcryptClient {
    pub rpc: LightClient,
    pub payer: Keypair,
}

impl SolcryptClient {
    /// Create a new client with the given keypair
    pub async fn new(payer: Keypair) -> Result<Self> {
        let config = LightClientConfig::devnet(
            Some("https://devnet.helius-rpc.com".to_string()),
            Some(std::env::var("HELIUS_API_KEY").unwrap()),
        );
        let mut rpc = LightClient::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create LightClient: {:?}", e))?;

        // Set the payer keypair
        rpc.payer = payer.insecure_clone();

        Ok(Self { rpc, payer })
    }

    /// Get the user's public key
    pub fn pubkey(&self) -> Pubkey {
        self.payer.pubkey()
    }

    /// Derive the UserAccount PDA for a given user
    pub fn get_user_pda(user: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[USER_SEED, user.as_ref()], &solcrypt_program::ID.into())
    }

    /// Check if a user account exists
    pub async fn user_account_exists(&self, user: &Pubkey) -> Result<bool> {
        let (pda, _) = Self::get_user_pda(user);
        let account = self
            .rpc
            .get_account(pda)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get account: {:?}", e))?;
        Ok(account.is_some())
    }

    /// Fetch a user's account data
    pub async fn get_user_account(&self, user: &Pubkey) -> Result<Option<UserAccount>> {
        let (pda, _) = Self::get_user_pda(user);
        let account = self
            .rpc
            .get_account(pda)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get account: {:?}", e))?;

        match account {
            Some(acc) => {
                let user_account = UserAccount::deserialize(&mut acc.data.as_slice())
                    .context("Failed to deserialize UserAccount")?;
                Ok(Some(user_account))
            }
            None => Ok(None),
        }
    }

    /// Get the X25519 public key for a user (needed for encryption)
    pub async fn get_user_x25519_pubkey(&self, user: &Pubkey) -> Result<Option<[u8; 32]>> {
        let account = self.get_user_account(user).await?;
        Ok(account.map(|a| a.x25519_pubkey))
    }

    /// Get threads for the current user, separated by status
    pub async fn get_threads(&self) -> Result<(Vec<ThreadEntry>, Vec<ThreadEntry>)> {
        let account = self
            .get_user_account(&self.payer.pubkey())
            .await?
            .context("User account not initialized")?;

        let mut accepted = Vec::new();
        let mut pending = Vec::new();

        for thread in account.threads {
            if thread.state == THREAD_STATE_ACCEPTED {
                accepted.push(thread);
            } else {
                pending.push(thread);
            }
        }

        Ok((accepted, pending))
    }

    /// Get validity proof for creating a new compressed account at the given address
    pub async fn get_validity_proof_for_new_address(
        &self,
        address: [u8; 32],
        address_tree: Pubkey,
    ) -> Result<ValidityProofWithContext> {
        let result = self
            .rpc
            .get_validity_proof(
                vec![],
                vec![AddressWithTree {
                    address,
                    tree: address_tree,
                }],
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

        Ok(result.value)
    }

    /// Fetch compressed messages for a thread
    /// Returns messages sorted by timestamp (oldest first)
    pub async fn get_messages_for_thread(&self, thread_id: [u8; 32]) -> Result<Vec<MsgV1>> {
        // Get all compressed accounts owned by our program
        let response = self
            .rpc
            .get_compressed_accounts_by_owner(&solcrypt_program::ID.into(), None, None)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch compressed accounts: {:?}", e))?;

        let mut messages: Vec<MsgV1> = Vec::new();

        for account in response.value.items {
            if let Some(data) = &account.data {
                // Try to deserialize as MsgV1
                if let Ok(msg) = MsgV1::deserialize(&mut data.data.as_slice()) {
                    if msg.thread_id == thread_id {
                        messages.push(msg);
                    }
                }
            }
        }

        // Sort by timestamp (oldest first)
        messages.sort_by_key(|m| m.unix_timestamp);

        Ok(messages)
    }

    /// Send a transaction and wait for confirmation
    pub async fn send_and_confirm_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<Signature> {
        let signature = self
            .rpc
            .process_transaction(transaction)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send transaction: {:?}", e))?;

        Ok(signature)
    }

    /// Get recent blockhash
    pub async fn get_recent_blockhash(&mut self) -> Result<solana_sdk::hash::Hash> {
        let (hash, _) = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get recent blockhash: {:?}", e))?;
        Ok(hash)
    }
}

/// Format a pubkey for display (abbreviated)
pub fn format_pubkey(pubkey: &Pubkey) -> String {
    let s = pubkey.to_string();
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}

/// Format a thread ID for display (abbreviated hex)
pub fn format_thread_id(thread_id: &[u8; 32]) -> String {
    let hex = hex::encode(thread_id);
    format!("{}...{}", &hex[..8], &hex[hex.len() - 8..])
}
