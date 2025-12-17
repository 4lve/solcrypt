#![cfg(feature = "test-sbf")]

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use borsh::{BorshDeserialize, BorshSerialize};
use light_program_test::{
    AddressWithTree, Indexer, ProgramTestConfig, Rpc, RpcError, program_test::LightProgramTest,
};
use light_sdk::address::v1::derive_address;
use light_sdk::instruction::{PackedAccounts, SystemAccountMetaConfig};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program::ID as SYSTEM_PROGRAM_ID;
use solcrypt_program::{
    AcceptThreadData, AddThreadData, InitUserData, InstructionType, MsgV1, RemoveThreadData,
    SendDmMessageData, USER_SEED, UserAccount,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Derives an X25519 keypair from a Solana signature.
///
/// Process:
/// 1. Sign a domain-specific message with the Solana keypair
/// 2. Hash the signature with SHA256 to get a 32-byte seed
/// 3. Use the seed to create an X25519 secret key
pub fn derive_x25519_keypair(solana_keypair: &Keypair) -> (X25519SecretKey, X25519PublicKey) {
    // Sign a domain-specific message to derive the X25519 seed
    let message = b"solcrypt-x25519-key-derivation-v1";
    let signature = solana_keypair.sign_message(message);

    // Hash the signature to get a 32-byte seed
    let mut hasher = Sha256::new();
    hasher.update(signature.as_ref());
    let seed: [u8; 32] = hasher.finalize().into();

    // Create X25519 keypair from seed
    let secret = X25519SecretKey::from(seed);
    let public = X25519PublicKey::from(&secret);

    (secret, public)
}

/// Computes the thread ID for a DM conversation between two parties.
///
/// thread_id = SHA256(min(a, b) || max(a, b) || "dm-v1")
///
/// This ensures both parties compute the same thread ID regardless of
/// who initiates the conversation.
pub fn compute_thread_id(a: &Pubkey, b: &Pubkey) -> [u8; 32] {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();

    // Order deterministically
    let (first, second) = if a_bytes < b_bytes {
        (&a_bytes, &b_bytes)
    } else {
        (&b_bytes, &a_bytes)
    };

    // SHA256(first || second || "dm-v1")
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"dm-v1");
    hasher.finalize().into()
}

/// Derives a shared secret between two X25519 keypairs using Diffie-Hellman.
/// Returns the AES-256 key derived from the shared secret.
pub fn derive_aes_key(our_secret: &X25519SecretKey, their_public: &X25519PublicKey) -> [u8; 32] {
    let shared_secret = our_secret.diffie_hellman(their_public);

    // Hash the shared secret to derive the AES key
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.finalize().into()
}

/// Encrypts a message using AES-256-GCM.
/// Returns (iv, ciphertext).
pub fn encrypt_message(aes_key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(aes_key).expect("Invalid key length");

    // Generate random IV
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");

    (iv, ciphertext)
}

/// Decrypts a message using AES-256-GCM.
pub fn decrypt_message(aes_key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(aes_key).expect("Invalid key length");
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, ciphertext)
        .expect("Decryption failed")
}

/// Generate a random nonce for message address derivation
fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive UserAccount PDA
fn get_user_pda(user: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[USER_SEED, user.as_ref()], program_id)
}

// ============================================================================
// Message Protocol (Client-side)
// ============================================================================

/// Message content enum - serialized before encryption.
/// This is a client-side protocol; the program only sees opaque ciphertext bytes.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq)]
#[repr(u8)]
pub enum Message {
    /// Plain text message (UTF-8)
    Text(String) = 0,
    // Future variants:
    // CompressedText { algo: u8, data: Vec<u8> },
    // File { name: String, mime: String, data: Vec<u8> },
    // Reaction { message_address: [u8; 32], emoji: String },
}

// ============================================================================
// Main Test
// ============================================================================

#[tokio::test]
async fn test_solcrypt_dm() {
    let config = ProgramTestConfig::new(
        true,
        Some(vec![("solcrypt_program", solcrypt_program::ID.into())]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();

    let program_id: Pubkey = solcrypt_program::ID.into();

    // Create other users for DM testing
    let recipient_keypair = Keypair::new();
    let third_user_keypair = Keypair::new();

    // ========================================================================
    // Derive X25519 keypairs for E2EE
    // ========================================================================
    println!("Deriving X25519 keypairs from Solana signatures...");
    let (sender_x25519_secret, sender_x25519_public) = derive_x25519_keypair(&payer);
    let (recipient_x25519_secret, recipient_x25519_public) =
        derive_x25519_keypair(&recipient_keypair);

    // Verify both parties derive the same shared secret
    let sender_aes_key = derive_aes_key(&sender_x25519_secret, &recipient_x25519_public);
    let recipient_aes_key = derive_aes_key(&recipient_x25519_secret, &sender_x25519_public);
    assert_eq!(
        sender_aes_key, recipient_aes_key,
        "Shared secrets must match!"
    );
    println!("  ✓ X25519 key exchange verified");

    // ========================================================================
    // Test 1: Initialize User Account (sender)
    // ========================================================================
    println!("Test 1: Initialize sender's UserAccount...");
    init_user(&payer, &mut rpc, sender_x25519_public.to_bytes())
        .await
        .unwrap();

    // Verify the user account was created
    let (user_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);
    let user_account_data = rpc.get_account(user_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.x25519_pubkey, sender_x25519_public.to_bytes());
    assert!(user_account.threads.is_empty());
    println!("  ✓ Sender UserAccount created with X25519 pubkey");

    // ========================================================================
    // Test 2: Send Encrypted DM Message
    // ========================================================================
    println!("Test 2: Send encrypted DM message...");

    let address_tree_info = rpc.get_address_tree_v1();
    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = rpc.get_random_state_tree_info_v1().unwrap().tree;

    // Compute thread ID using SHA256
    let thread_id = compute_thread_id(&payer.pubkey(), &recipient_keypair.pubkey());
    let nonce = random_nonce();

    // Create and serialize the message
    let message = Message::Text("Hello from Solcrypt! This is an E2EE message.".into());
    let plaintext = message.try_to_vec().unwrap();

    // Encrypt the serialized message
    let (iv, ciphertext) = encrypt_message(&sender_aes_key, &plaintext);

    println!("  Message: {:?}", message);
    println!("  Serialized size: {} bytes", plaintext.len());
    println!(
        "  Ciphertext size: {} bytes (includes 16-byte auth tag)",
        ciphertext.len()
    );

    // Derive the message address
    let (msg_address, _) = derive_address(
        &[b"msg", &thread_id, &nonce],
        &address_tree_pubkey,
        &program_id,
    );

    send_dm_message(
        &payer,
        &mut rpc,
        &merkle_tree_pubkey,
        address_tree_pubkey,
        msg_address,
        thread_id,
        recipient_keypair.pubkey(),
        iv,
        ciphertext.clone(),
        nonce,
    )
    .await
    .unwrap();

    // Verify the message was created and can be decrypted
    let compressed_msg = rpc
        .get_compressed_account(msg_address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    assert_eq!(compressed_msg.address.unwrap(), msg_address);

    let msg =
        MsgV1::deserialize(&mut compressed_msg.data.as_ref().unwrap().data.as_slice()).unwrap();
    assert_eq!(msg.thread_id, thread_id);
    assert_eq!(msg.sender, payer.pubkey().to_bytes());
    assert_eq!(msg.recipient, recipient_keypair.pubkey().to_bytes());
    assert_eq!(msg.iv, iv);
    assert_eq!(msg.ciphertext, ciphertext);

    // Decrypt and deserialize the message content
    let decrypted_bytes = decrypt_message(&recipient_aes_key, &msg.iv, &msg.ciphertext);
    let decrypted_message = Message::deserialize(&mut decrypted_bytes.as_slice()).unwrap();
    assert_eq!(decrypted_message, message);
    println!("  ✓ Message encrypted and stored on-chain");
    println!("  ✓ Recipient decrypted: {:?}", decrypted_message);

    // ========================================================================
    // Test 3: Add thread to sender's list (accepted state)
    // ========================================================================
    println!("Test 3: Add thread to sender's list...");
    add_thread(
        &payer,
        &mut rpc,
        thread_id,
        solcrypt_program::THREAD_STATE_ACCEPTED,
    )
    .await
    .unwrap();

    // Verify thread was added
    let user_account_data = rpc.get_account(user_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 1);
    assert_eq!(user_account.threads[0].thread_id, thread_id);
    assert_eq!(
        user_account.threads[0].state,
        solcrypt_program::THREAD_STATE_ACCEPTED
    );
    println!("  ✓ Thread added to sender's list");

    // ========================================================================
    // Test 4: Add Thread as pending (simulating a different conversation)
    // ========================================================================
    println!("Test 4: Add pending thread...");
    let pending_thread_id = compute_thread_id(&payer.pubkey(), &third_user_keypair.pubkey());
    add_thread(
        &payer,
        &mut rpc,
        pending_thread_id,
        solcrypt_program::THREAD_STATE_PENDING,
    )
    .await
    .unwrap();

    // Verify pending thread was added
    let user_account_data = rpc.get_account(user_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 2);
    assert_eq!(
        user_account.threads[1].state,
        solcrypt_program::THREAD_STATE_PENDING
    );
    println!("  ✓ Pending thread added");

    // ========================================================================
    // Test 5: Accept Thread
    // ========================================================================
    println!("Test 5: Accept pending thread...");
    accept_thread(&payer, &mut rpc, pending_thread_id)
        .await
        .unwrap();

    // Verify thread was accepted
    let user_account_data = rpc.get_account(user_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(
        user_account.threads[1].state,
        solcrypt_program::THREAD_STATE_ACCEPTED
    );
    println!("  ✓ Thread accepted");

    // ========================================================================
    // Test 6: Remove Thread
    // ========================================================================
    println!("Test 6: Remove thread...");
    remove_thread(&payer, &mut rpc, pending_thread_id)
        .await
        .unwrap();

    // Verify thread was removed
    let user_account_data = rpc.get_account(user_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 1);
    assert_eq!(user_account.threads[0].thread_id, thread_id);
    println!("  ✓ Thread removed");

    println!("\n✅ All tests passed! E2EE messaging verified.");
}

// ============================================================================
// Instruction Helpers
// ============================================================================

/// Initialize a user account PDA with X25519 public key
pub async fn init_user(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    x25519_pubkey: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);

    let instruction_data = InitUserData { x25519_pubkey };
    let inputs = instruction_data.try_to_vec().unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: [&[InstructionType::InitUser as u8][..], &inputs[..]].concat(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

/// Send a DM message (creates compressed MsgV1 account)
pub async fn send_dm_message(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    merkle_tree_pubkey: &Pubkey,
    address_tree_pubkey: Pubkey,
    address: [u8; 32],
    thread_id: [u8; 32],
    recipient: Pubkey,
    iv: [u8; 12],
    ciphertext: Vec<u8>,
    nonce: [u8; 32],
) -> Result<(), RpcError> {
    let system_account_meta_config = SystemAccountMetaConfig::new(solcrypt_program::ID.into());
    let mut accounts = PackedAccounts::default();
    accounts.add_pre_accounts_signer(payer.pubkey());
    accounts.add_system_accounts(system_account_meta_config)?;

    let rpc_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await?
        .value;

    let output_merkle_tree_index = accounts.insert_or_get(*merkle_tree_pubkey);
    let packed_address_tree_info = rpc_result.pack_tree_infos(&mut accounts).address_trees[0];
    let (accounts, _, _) = accounts.to_account_metas();

    let instruction_data = SendDmMessageData {
        proof: rpc_result.proof,
        address_tree_info: packed_address_tree_info,
        output_state_tree_index: output_merkle_tree_index,
        thread_id,
        recipient: recipient.to_bytes().into(),
        iv,
        ciphertext,
        nonce,
    };
    let inputs = instruction_data.try_to_vec().unwrap();

    let instruction = Instruction {
        program_id: solcrypt_program::ID.into(),
        accounts,
        data: [&[InstructionType::SendDmMessage as u8][..], &inputs[..]].concat(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

/// Add a thread to the user's thread list
pub async fn add_thread(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    thread_id: [u8; 32],
    state: u8,
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);

    let instruction_data = AddThreadData { thread_id, state };
    let inputs = instruction_data.try_to_vec().unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: [&[InstructionType::AddThread as u8][..], &inputs[..]].concat(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

/// Accept a pending thread
pub async fn accept_thread(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    thread_id: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);

    let instruction_data = AcceptThreadData { thread_id };
    let inputs = instruction_data.try_to_vec().unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: [&[InstructionType::AcceptThread as u8][..], &inputs[..]].concat(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

/// Remove a thread from the user's thread list
pub async fn remove_thread(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    thread_id: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);

    let instruction_data = RemoveThreadData { thread_id };
    let inputs = instruction_data.try_to_vec().unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: [&[InstructionType::RemoveThread as u8][..], &inputs[..]].concat(),
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}
