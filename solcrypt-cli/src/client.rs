//! RPC client wrapper for Solcrypt operations.
//!
//! Provides functionality for:
//! - Connecting to the Helius devnet RPC
//! - Fetching UserAccount PDAs
//! - Querying compressed message accounts

use anyhow::{Context, Result};
use light_client::{
    indexer::{
        AddressWithTree, GetCompressedAccountsByOwnerConfig, GetCompressedAccountsFilter, Indexer,
        ValidityProofWithContext,
    },
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
use solcrypt_program::{
    GroupAccount, GroupKeyV1, GroupMsgV1, MsgV1, ThreadEntry, UserAccount, GROUP_KEY_SEED,
    GROUP_SEED, USER_SEED,
};
use wincode::Deserialize as WincodeDeserialize;

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
                let user_account = UserAccount::deserialize(acc.data.as_slice())
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

    // ========================================================================
    // Group Account Functions
    // ========================================================================

    /// Derive the GroupAccount PDA for a given group ID
    pub fn get_group_pda(group_id: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[GROUP_SEED, group_id.as_ref()],
            &solcrypt_program::ID.into(),
        )
    }

    /// Fetch a group account
    pub async fn get_group_account(&self, group_id: &[u8; 32]) -> Result<Option<GroupAccount>> {
        let (pda, _) = Self::get_group_pda(group_id);
        let account = self
            .rpc
            .get_account(pda)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get group account: {:?}", e))?;

        match account {
            Some(acc) => {
                let group_account = GroupAccount::deserialize(acc.data.as_slice())
                    .context("Failed to deserialize GroupAccount")?;
                Ok(Some(group_account))
            }
            None => Ok(None),
        }
    }

    /// Fetch the current user's GroupKeyV1 for a group
    /// Returns the GroupKeyV1 data, address, and hash (for ZK proofs)
    pub async fn get_my_group_key(
        &self,
        group_id: &[u8; 32],
    ) -> Result<Option<(GroupKeyV1, [u8; 32])>> {
        // Get the group account to know the current key version
        let group_account = match self.get_group_account(group_id).await? {
            Some(acc) => acc,
            None => return Ok(None),
        };

        // Derive the address for the user's GroupKeyV1
        let address_tree_info = self.rpc.get_address_tree_v1();
        let key_version_bytes = group_account.current_key_version.to_le_bytes();

        let (key_address, _) = derive_address(
            &[
                GROUP_KEY_SEED,
                group_id,
                self.payer.pubkey().as_ref(),
                &key_version_bytes,
            ],
            &address_tree_info.tree,
            &solcrypt_program::ID.into(),
        );

        // Fetch the compressed account
        match self
            .rpc
            .get_compressed_account(key_address, None)
            .await?
            .value
        {
            Some(account) => {
                let group_key =
                    GroupKeyV1::deserialize(&account.data.as_ref().unwrap().data.as_slice())
                        .context("Failed to deserialize GroupKeyV1")?;

                Ok(Some((group_key, key_address)))
            }
            None => Ok(None),
        }
    }

    /// Fetch GroupKeyV1 with full account metadata for ZK proofs
    /// Returns: (GroupKeyV1, address, hash)
    pub async fn get_my_group_key_with_hash(
        &self,
        group_id: &[u8; 32],
    ) -> Result<Option<(GroupKeyV1, [u8; 32], [u8; 32])>> {
        // Get the group account to know the current key version
        let group_account = match self.get_group_account(group_id).await? {
            Some(acc) => acc,
            None => return Ok(None),
        };

        // Derive the address for the user's GroupKeyV1
        let address_tree_info = self.rpc.get_address_tree_v1();
        let key_version_bytes = group_account.current_key_version.to_le_bytes();

        let (key_address, _) = derive_address(
            &[
                GROUP_KEY_SEED,
                group_id,
                self.payer.pubkey().as_ref(),
                &key_version_bytes,
            ],
            &address_tree_info.tree,
            &solcrypt_program::ID.into(),
        );

        // Fetch the compressed account
        match self
            .rpc
            .get_compressed_account(key_address, None)
            .await?
            .value
        {
            Some(account) => {
                let group_key =
                    GroupKeyV1::deserialize(&account.data.as_ref().unwrap().data.as_slice())
                        .context("Failed to deserialize GroupKeyV1")?;

                Ok(Some((group_key, key_address, account.hash)))
            }
            None => Ok(None),
        }
    }

    /// Get validity proof for an existing compressed account (for updates/closes)
    pub async fn get_validity_proof_for_account(
        &self,
        address: [u8; 32],
    ) -> Result<ValidityProofWithContext> {
        // For reading existing accounts, we put the address in the first vec (hashes)
        let result = self
            .rpc
            .get_validity_proof(vec![address], vec![], None)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get validity proof: {:?}", e))?;

        Ok(result.value)
    }

    /// Fetch group messages for a group
    pub async fn get_group_messages(&self, group_id: &[u8; 32]) -> Result<Vec<GroupMsgV1>> {
        let messages = self
            .rpc
            .get_compressed_accounts_by_owner(
                &solcrypt_program::ID.into(),
                Some(GetCompressedAccountsByOwnerConfig {
                    filters: Some(vec![GetCompressedAccountsFilter {
                        bytes: group_id.to_vec(),
                        offset: 1, // After discriminator
                    }]),
                    data_slice: None,
                    cursor: None,
                    limit: None,
                }),
                None,
            )
            .await?;

        let mut msgs: Vec<GroupMsgV1> = messages
            .value
            .items
            .iter()
            .filter_map(|acc| {
                // Filter for GroupMsgV1 accounts (discriminator = 4)
                let data = acc.data.as_ref()?.data.as_slice();
                if data.is_empty() || data[0] != 4 {
                    return None;
                }
                GroupMsgV1::deserialize(data).ok()
            })
            .collect();

        msgs.sort_by_key(|m| m.unix_timestamp);
        Ok(msgs)
    }

    /// Derive GroupKeyV1 address for a member
    pub fn derive_group_key_address(
        &self,
        group_id: &[u8; 32],
        member: &Pubkey,
        key_version: u32,
    ) -> [u8; 32] {
        let address_tree_info = self.rpc.get_address_tree_v1();
        let key_version_bytes = key_version.to_le_bytes();

        let (address, _) = derive_address(
            &[
                GROUP_KEY_SEED,
                group_id,
                member.as_ref(),
                &key_version_bytes,
            ],
            &address_tree_info.tree,
            &solcrypt_program::ID.into(),
        );

        address
    }

    /// Get DM threads for the current user, separated by status
    pub async fn get_dm_threads(&self) -> Result<(Vec<ThreadEntry>, Vec<ThreadEntry>)> {
        let account = self
            .get_user_account(&self.payer.pubkey())
            .await?
            .context("User account not initialized")?;

        let mut accepted = Vec::new();
        let mut pending = Vec::new();

        for thread in account.threads {
            // Skip group threads
            if thread.is_group() {
                continue;
            }
            if thread.is_accepted() {
                accepted.push(thread);
            } else {
                pending.push(thread);
            }
        }

        Ok((accepted, pending))
    }

    /// Get group threads for the current user, separated by status
    pub async fn get_group_threads(&self) -> Result<(Vec<ThreadEntry>, Vec<ThreadEntry>)> {
        let account = self
            .get_user_account(&self.payer.pubkey())
            .await?
            .context("User account not initialized")?;

        let mut accepted = Vec::new();
        let mut pending = Vec::new();

        for thread in account.threads {
            // Only include group threads
            if !thread.is_group() {
                continue;
            }
            if thread.is_accepted() {
                accepted.push(thread);
            } else {
                pending.push(thread);
            }
        }

        Ok((accepted, pending))
    }

    /// Get all threads for the current user (legacy, for compatibility)
    pub async fn get_threads(&self) -> Result<(Vec<ThreadEntry>, Vec<ThreadEntry>)> {
        self.get_dm_threads().await
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
        let messages = self
            .rpc
            .get_compressed_accounts_by_owner(
                &solcrypt_program::ID.into(),
                Some(GetCompressedAccountsByOwnerConfig {
                    filters: Some(vec![GetCompressedAccountsFilter {
                        bytes: thread_id.to_vec(),
                        offset: 1,
                    }]),
                    data_slice: None,
                    cursor: None,
                    limit: None,
                }),
                None, // Get all messages for the thread
            )
            .await?;

        let mut messages: Vec<MsgV1> = messages
            .value
            .items
            .iter()
            .map(|acc| MsgV1::deserialize(&acc.data.as_ref().unwrap().data.as_slice()).unwrap())
            .collect();

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
            .rpc
            .get_compressed_account(first_msg_address, None)
            .await?
            .value
        {
            Some(account) => {
                let msg =
                    MsgV1::deserialize(&account.data.as_ref().unwrap().data.as_slice()).unwrap();
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

/// Format a group ID for display (abbreviated hex)
pub fn format_group_id(group_id: &[u8; 32]) -> String {
    let hex = hex::encode(group_id);
    format!("Group {}..{}", &hex[..6], &hex[hex.len() - 4..])
}
