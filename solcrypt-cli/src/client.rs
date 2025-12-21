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
use light_sdk::address::v1::derive_address;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::Transaction,
};
use solcrypt_program::{MsgV1, ThreadEntry, UserAccount, THREAD_STATE_ACCEPTED, USER_SEED};

// ============================================================================
// Custom Photon API types (with correct base58 encoding for memcmp)
// ============================================================================

#[derive(Debug, Serialize)]
struct PhotonRequest<T> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'static str,
    params: T,
}

#[derive(Debug, Serialize)]
struct GetCompressedAccountsByOwnerParams {
    owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    filters: Option<Vec<PhotonFilterSelector>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct PhotonFilterSelector {
    memcmp: PhotonMemcmp,
}

#[derive(Debug, Serialize)]
struct PhotonMemcmp {
    offset: u32,
    bytes: String, // Base58 encoded!
}

#[derive(Debug, Deserialize)]
struct PhotonResponse<T> {
    result: Option<T>,
    error: Option<PhotonError>,
}

#[derive(Debug, Deserialize)]
struct PhotonError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct PhotonAccountsResult {
    value: PhotonAccountList,
}

#[derive(Debug, Deserialize)]
struct PhotonAccountList {
    items: Vec<PhotonAccount>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PhotonAccount {
    hash: String,
    owner: String,
    data: Option<PhotonAccountData>,
}

#[derive(Debug, Deserialize)]
struct PhotonAccountData {
    data: String, // Base64 encoded
    discriminator: u64,
}

/// Client for interacting with the Solcrypt program
pub struct SolcryptClient {
    pub rpc: LightClient,
    pub payer: Keypair,
    http_client: reqwest::Client,
    rpc_url: String,
}

impl SolcryptClient {
    /// Create a new client with the given keypair
    pub async fn new(payer: Keypair) -> Result<Self> {
        let api_key = std::env::var("HELIUS_API_KEY")
            .context("HELIUS_API_KEY environment variable not set")?;
        let rpc_url = format!("https://devnet.helius-rpc.com?api-key={}", api_key);

        let config = LightClientConfig::devnet(
            Some("https://devnet.helius-rpc.com".to_string()),
            Some(api_key),
        );
        let mut rpc = LightClient::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create LightClient: {:?}", e))?;

        // Set the payer keypair
        rpc.payer = payer.insecure_clone();

        let http_client = reqwest::Client::new();

        Ok(Self {
            rpc,
            payer,
            http_client,
            rpc_url,
        })
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

    /// Custom getCompressedAccountsByOwner with proper base58 memcmp encoding
    /// (light-client uses base64 which is wrong per Photon API spec)
    async fn get_compressed_accounts_by_owner_custom(
        &self,
        owner: &Pubkey,
        thread_id_filter: Option<[u8; 32]>,
        limit: Option<u16>,
    ) -> Result<Vec<MsgV1>> {
        let filters = thread_id_filter.map(|tid| {
            vec![PhotonFilterSelector {
                memcmp: PhotonMemcmp {
                    offset: 0, // thread_id is the first field
                    bytes: bs58::encode(&tid).into_string(),
                },
            }]
        });

        let params = GetCompressedAccountsByOwnerParams {
            owner: owner.to_string(),
            filters,
            limit,
            cursor: None,
        };

        let request = PhotonRequest {
            jsonrpc: "2.0",
            id: "1",
            method: "getCompressedAccountsByOwner",
            params,
        };

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Photon API")?;

        let result: PhotonResponse<PhotonAccountsResult> = response
            .json()
            .await
            .context("Failed to parse Photon API response")?;

        if let Some(error) = result.error {
            anyhow::bail!("Photon API error {}: {}", error.code, error.message);
        }

        let accounts = result.result.context("No result in Photon API response")?;

        let mut messages: Vec<MsgV1> = Vec::new();

        for account in accounts.value.items {
            if let Some(data) = account.data {
                // Decode base64 data
                let bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data.data)
                        .context("Failed to decode base64 account data")?;

                if let Ok(msg) = MsgV1::deserialize(&mut bytes.as_slice()) {
                    messages.push(msg);
                }
            }
        }

        Ok(messages)
    }

    /// Fetch compressed messages for a thread
    /// Returns messages sorted by timestamp (oldest first)
    pub async fn get_messages_for_thread(&self, thread_id: [u8; 32]) -> Result<Vec<MsgV1>> {
        let mut messages = self
            .get_compressed_accounts_by_owner_custom(
                &solcrypt_program::ID.into(),
                Some(thread_id),
                None, // Get all messages for the thread
            )
            .await?;

        // Sort by timestamp (oldest first)
        messages.sort_by_key(|m| m.unix_timestamp);

        Ok(messages)
    }

    /// Get the other party's pubkey for a thread by fetching the first message (nonce=0).
    ///
    /// This uses O(1) lookup since the first message always has nonce=0, allowing us to
    /// derive its address deterministically without querying all messages.
    ///
    /// Returns None if the first message doesn't exist.
    pub async fn get_other_party_for_thread(
        &self,
        thread_id: [u8; 32],
        my_pubkey: &Pubkey,
    ) -> Result<Option<Pubkey>> {
        // Get the address tree to derive the first message's address
        let address_tree_info = self.rpc.get_address_tree_v1();
        let address_tree_pubkey = address_tree_info.tree;

        // The first message always uses nonce=0
        let nonce = [0u8; 32];

        // Derive the first message's address deterministically
        let (first_msg_address, _) = derive_address(
            &[b"msg", &thread_id, &nonce],
            &address_tree_pubkey,
            &solcrypt_program::ID.into(),
        );

        // Try to fetch the first message directly by its derived address
        match self
            .get_compressed_account_by_address(&first_msg_address)
            .await?
        {
            Some(msg) => {
                let sender = Pubkey::from(msg.sender);
                let recipient = Pubkey::from(msg.recipient);

                // Return the other party (not me)
                if sender == *my_pubkey {
                    Ok(Some(recipient))
                } else {
                    Ok(Some(sender))
                }
            }
            None => Ok(None),
        }
    }

    /// Get a compressed account by its specific address (O(1) lookup)
    async fn get_compressed_account_by_address(&self, address: &[u8; 32]) -> Result<Option<MsgV1>> {
        // Photon API: getCompressedAccount
        #[derive(Debug, Serialize)]
        struct GetCompressedAccountParams {
            address: String, // Base58 encoded address
        }

        let params = GetCompressedAccountParams {
            address: bs58::encode(address).into_string(),
        };

        let request = PhotonRequest {
            jsonrpc: "2.0",
            id: "1",
            method: "getCompressedAccount",
            params,
        };

        let response = self
            .http_client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Photon API")?;

        let result: PhotonResponse<Option<PhotonAccount>> = response
            .json()
            .await
            .context("Failed to parse Photon API response")?;

        if let Some(error) = result.error {
            anyhow::bail!("Photon API error {}: {}", error.code, error.message);
        }

        match result.result {
            Some(Some(account)) => {
                if let Some(data) = account.data {
                    let bytes = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &data.data,
                    )
                    .context("Failed to decode base64 account data")?;

                    if let Ok(msg) = MsgV1::deserialize(&mut bytes.as_slice()) {
                        return Ok(Some(msg));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
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
