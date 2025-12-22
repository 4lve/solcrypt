#![cfg(feature = "test-sbf")]

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use light_program_test::{
    AddressWithTree, Indexer, ProgramTestConfig, Rpc, RpcError, program_test::LightProgramTest,
};
use light_sdk::address::v1::derive_address;
use light_sdk::instruction::{PackedAccounts, SystemAccountMetaConfig};
use sha2::{Digest, Sha256};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program::ID as SYSTEM_PROGRAM_ID;
use solcrypt_program::{
    AcceptGroupInviteData, AcceptThreadData, AddThreadData, ClientSideMessage, CreateGroupData,
    GROUP_KEY_SEED, GROUP_SEED, GroupAccount, GroupKeyV1, InitUserData, InstructionType, MsgV1,
    ROLE_OWNER, RemoveThreadData, SendDmMessageData, THREAD_STATE_GROUP_ACCEPTED, USER_SEED,
    UserAccount,
};
use wincode::{Deserialize, Serialize};
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

/// Derive UserAccount PDA
fn get_user_pda(user: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[USER_SEED, user.as_ref()], program_id)
}

/// Derive GroupAccount PDA
fn get_group_pda(group_id: &[u8; 32], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[GROUP_SEED, group_id], program_id)
}

/// Generate a random group ID
fn random_group_id() -> [u8; 32] {
    let mut group_id = [0u8; 32];
    OsRng.fill_bytes(&mut group_id);
    group_id
}

/// Generate a random AES-256 key for group encryption
fn generate_group_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt an AES key for a member using NaCl box (simplified - in real app use proper NaCl box)
/// For testing, we just store the key with padding to simulate the 48-byte encrypted format
fn encrypt_aes_key_for_member(aes_key: &[u8; 32], _member_x25519_pubkey: &[u8; 32]) -> [u8; 48] {
    // In a real implementation, this would use crypto_box_seal or similar
    // For testing, we just copy the key and add padding
    let mut encrypted = [0u8; 48];
    encrypted[..32].copy_from_slice(aes_key);
    // Remaining 16 bytes would be auth tag in real NaCl box
    encrypted
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
    // Test 1a: Initialize User Account (sender)
    // ========================================================================
    println!("Test 1a: Initialize sender's UserAccount...");
    init_user(&payer, &mut rpc, sender_x25519_public.to_bytes())
        .await
        .unwrap();

    // Verify the user account was created
    let (sender_pda, _bump) = get_user_pda(&payer.pubkey(), &program_id);
    let user_account_data = rpc.get_account(sender_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.x25519_pubkey, sender_x25519_public.to_bytes());
    assert!(user_account.threads.is_empty());
    println!("  ✓ Sender UserAccount created with X25519 pubkey");

    // ========================================================================
    // Test 1b: Initialize User Account (recipient)
    // ========================================================================
    println!("Test 1b: Initialize recipient's UserAccount...");

    rpc.airdrop_lamports(&recipient_keypair.pubkey(), LAMPORTS_PER_SOL)
        .await
        .unwrap();

    // Fund recipient so they can pay for their own init (in real scenario)
    init_user(
        &recipient_keypair,
        &mut rpc,
        recipient_x25519_public.to_bytes(),
    )
    .await
    .unwrap();

    let (recipient_pda, _) = get_user_pda(&recipient_keypair.pubkey(), &program_id);
    let recipient_account_data = rpc.get_account(recipient_pda).await.unwrap().unwrap();
    let recipient_account =
        UserAccount::deserialize(&mut &recipient_account_data.data[..]).unwrap();
    assert_eq!(
        recipient_account.x25519_pubkey,
        recipient_x25519_public.to_bytes()
    );
    println!("  ✓ Recipient UserAccount created with X25519 pubkey");

    // ========================================================================
    // Test 2: Send Encrypted DM Message (auto-adds threads to both accounts)
    // ========================================================================
    println!("Test 2: Send encrypted DM message...");

    let address_tree_info = rpc.get_address_tree_v1();
    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = rpc.get_random_state_tree_info_v1().unwrap().tree;

    // Compute thread ID using SHA256
    let thread_id = compute_thread_id(&payer.pubkey(), &recipient_keypair.pubkey());
    // First message in a thread has a nonce of 0
    let nonce = [0u8; 32];

    // Create and serialize the message
    let message = ClientSideMessage::Text("Hello from Solcrypt! This is an E2EE message.".into());
    let plaintext = ClientSideMessage::serialize(&message).unwrap();

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
    let decrypted_message =
        ClientSideMessage::deserialize(&mut decrypted_bytes.as_slice()).unwrap();
    assert_eq!(decrypted_message, message);
    println!("  ✓ Message encrypted and stored on-chain");
    println!("  ✓ Recipient decrypted: {:?}", decrypted_message);

    // Verify thread was auto-added to sender's list (ACCEPTED)
    let user_account_data = rpc.get_account(sender_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 1);
    assert_eq!(user_account.threads[0].thread_id, thread_id);
    assert_eq!(
        user_account.threads[0].state,
        solcrypt_program::THREAD_STATE_ACCEPTED
    );
    println!("  ✓ Thread auto-added to sender's list (ACCEPTED)");

    // Verify thread was auto-added to recipient's list (PENDING)
    let recipient_account_data = rpc.get_account(recipient_pda).await.unwrap().unwrap();
    let recipient_account =
        UserAccount::deserialize(&mut &recipient_account_data.data[..]).unwrap();
    assert_eq!(recipient_account.threads.len(), 1);
    assert_eq!(recipient_account.threads[0].thread_id, thread_id);
    assert_eq!(
        recipient_account.threads[0].state,
        solcrypt_program::THREAD_STATE_PENDING
    );
    println!("  ✓ Thread auto-added to recipient's list (PENDING)");

    // ========================================================================
    // Test 3: Recipient accepts the thread (DM request flow)
    // ========================================================================
    println!("Test 3: Recipient accepts thread...");
    accept_thread_for(&payer, &recipient_keypair, &mut rpc, thread_id)
        .await
        .unwrap();

    // Verify thread was accepted
    let recipient_account_data = rpc.get_account(recipient_pda).await.unwrap().unwrap();
    let recipient_account =
        UserAccount::deserialize(&mut &recipient_account_data.data[..]).unwrap();
    assert_eq!(
        recipient_account.threads[0].state,
        solcrypt_program::THREAD_STATE_ACCEPTED
    );
    println!("  ✓ Recipient accepted the DM request");

    // ========================================================================
    // Test 4: Manual add thread (for testing add_thread separately)
    // ========================================================================
    println!("Test 4: Add another thread manually...");
    let manual_thread_id = compute_thread_id(&payer.pubkey(), &third_user_keypair.pubkey());
    add_thread(
        &payer,
        &mut rpc,
        manual_thread_id,
        solcrypt_program::THREAD_STATE_PENDING,
    )
    .await
    .unwrap();

    // Verify thread was added
    let user_account_data = rpc.get_account(sender_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 2);
    assert_eq!(
        user_account.threads[1].state,
        solcrypt_program::THREAD_STATE_PENDING
    );
    println!("  ✓ Manual thread added");

    // ========================================================================
    // Test 5: Accept the manually added thread
    // ========================================================================
    println!("Test 5: Accept manual thread...");
    accept_thread(&payer, &mut rpc, manual_thread_id)
        .await
        .unwrap();

    // Verify thread was accepted
    let user_account_data = rpc.get_account(sender_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(
        user_account.threads[1].state,
        solcrypt_program::THREAD_STATE_ACCEPTED
    );
    println!("  ✓ Manual thread accepted");

    // ========================================================================
    // Test 6: Remove Thread
    // ========================================================================
    println!("Test 6: Remove thread...");
    remove_thread(&payer, &mut rpc, manual_thread_id)
        .await
        .unwrap();

    // Verify thread was removed
    let user_account_data = rpc.get_account(sender_pda).await.unwrap().unwrap();
    let user_account = UserAccount::deserialize(&mut &user_account_data.data[..]).unwrap();
    assert_eq!(user_account.threads.len(), 1);
    assert_eq!(user_account.threads[0].thread_id, thread_id);
    println!("  ✓ Thread removed");

    println!("\n✅ All DM tests passed! E2EE messaging verified.");
}

// ============================================================================
// Group Chat Test
// ============================================================================

#[tokio::test]
async fn test_solcrypt_group() {
    let config = ProgramTestConfig::new(
        true,
        Some(vec![("solcrypt_program", solcrypt_program::ID.into())]),
    );
    let mut rpc = LightProgramTest::new(config).await.unwrap();
    let payer = rpc.get_payer().insecure_clone();

    let program_id: Pubkey = solcrypt_program::ID.into();

    // Create other users for group testing
    let member1_keypair = Keypair::new();
    let member2_keypair = Keypair::new();

    // ========================================================================
    // Derive X25519 keypairs for E2EE
    // ========================================================================
    println!("Deriving X25519 keypairs...");
    let (_, owner_x25519_public) = derive_x25519_keypair(&payer);
    let (_, member1_x25519_public) = derive_x25519_keypair(&member1_keypair);
    let (_, member2_x25519_public) = derive_x25519_keypair(&member2_keypair);

    // ========================================================================
    // Initialize User Accounts
    // ========================================================================
    println!("Test 1: Initialize user accounts...");

    // Initialize owner
    init_user(&payer, &mut rpc, owner_x25519_public.to_bytes())
        .await
        .unwrap();
    println!("  ✓ Owner UserAccount created");

    // Initialize member1
    rpc.airdrop_lamports(&member1_keypair.pubkey(), LAMPORTS_PER_SOL)
        .await
        .unwrap();
    init_user(&member1_keypair, &mut rpc, member1_x25519_public.to_bytes())
        .await
        .unwrap();
    println!("  ✓ Member1 UserAccount created");

    // Initialize member2
    rpc.airdrop_lamports(&member2_keypair.pubkey(), LAMPORTS_PER_SOL)
        .await
        .unwrap();
    init_user(&member2_keypair, &mut rpc, member2_x25519_public.to_bytes())
        .await
        .unwrap();
    println!("  ✓ Member2 UserAccount created");

    // ========================================================================
    // Test 2: Create Group
    // ========================================================================
    println!("Test 2: Create group...");

    let group_id = random_group_id();
    let group_aes_key = generate_group_aes_key();
    let owner_encrypted_key =
        encrypt_aes_key_for_member(&group_aes_key, &owner_x25519_public.to_bytes());

    let address_tree_info = rpc.get_address_tree_v1();
    let address_tree_pubkey = address_tree_info.tree;
    let merkle_tree_pubkey = rpc.get_random_state_tree_info_v1().unwrap().tree;

    // Derive the owner's GroupKeyV1 address
    let key_version_bytes = 1u32.to_le_bytes();
    let (owner_key_address, _) = derive_address(
        &[
            GROUP_KEY_SEED,
            &group_id,
            payer.pubkey().as_ref(),
            &key_version_bytes,
        ],
        &address_tree_pubkey,
        &program_id,
    );

    create_group(
        &payer,
        &mut rpc,
        &merkle_tree_pubkey,
        address_tree_pubkey,
        owner_key_address,
        group_id,
        owner_encrypted_key,
    )
    .await
    .unwrap();

    // Verify GroupAccount was created
    let (group_pda, _) = get_group_pda(&group_id, &program_id);
    let group_account_data = rpc.get_account(group_pda).await.unwrap().unwrap();
    let group_account = GroupAccount::deserialize(&mut &group_account_data.data[..]).unwrap();
    assert_eq!(group_account.group_id, group_id);
    // Compare owner bytes (pinocchio Pubkey vs solana_sdk Pubkey)
    let owner_bytes: [u8; 32] = group_account.owner.into();
    assert_eq!(owner_bytes, payer.pubkey().to_bytes());
    assert_eq!(group_account.current_key_version, 1);
    println!("  ✓ GroupAccount created");

    // Verify owner's GroupKeyV1 was created
    let owner_key_account = rpc
        .get_compressed_account(owner_key_address, None)
        .await
        .unwrap()
        .value
        .unwrap();
    let owner_key =
        GroupKeyV1::deserialize(&mut owner_key_account.data.as_ref().unwrap().data.as_slice())
            .unwrap();
    assert_eq!(owner_key.group_id, group_id);
    let member_bytes: [u8; 32] = owner_key.member.into();
    assert_eq!(member_bytes, payer.pubkey().to_bytes());
    assert_eq!(owner_key.key_version, 1);
    assert_eq!(owner_key.role, ROLE_OWNER);
    println!("  ✓ Owner's GroupKeyV1 created with ROLE_OWNER");

    // Verify thread was added to owner's UserAccount
    let (owner_pda, _) = get_user_pda(&payer.pubkey(), &program_id);
    let owner_user_data = rpc.get_account(owner_pda).await.unwrap().unwrap();
    let owner_user = UserAccount::deserialize(&mut &owner_user_data.data[..]).unwrap();
    assert_eq!(owner_user.threads.len(), 1);
    assert_eq!(owner_user.threads[0].thread_id, group_id);
    assert_eq!(owner_user.threads[0].state, THREAD_STATE_GROUP_ACCEPTED);
    assert!(owner_user.threads[0].is_group());
    assert!(owner_user.threads[0].is_accepted());
    println!("  ✓ Group thread added to owner's UserAccount (ACCEPTED)");

    // ========================================================================
    // Test 3: Accept Group Invite
    // ========================================================================
    // Note: In a full test, we would first invite member1, but that requires
    // reading the owner's compressed account which needs additional setup.
    // For now, we test accept_group_invite by manually adding a pending thread.
    println!("Test 3: Accept group invite flow...");

    // Manually add a pending group thread to member1 (simulating an invite)
    add_thread(
        &member1_keypair,
        &mut rpc,
        group_id,
        solcrypt_program::THREAD_STATE_GROUP_PENDING,
    )
    .await
    .unwrap();

    // Member1 accepts the invite
    accept_group_invite(&member1_keypair, &mut rpc, group_id)
        .await
        .unwrap();

    // Verify thread was accepted
    let (member1_pda, _) = get_user_pda(&member1_keypair.pubkey(), &program_id);
    let member1_user_data = rpc.get_account(member1_pda).await.unwrap().unwrap();
    let member1_user = UserAccount::deserialize(&mut &member1_user_data.data[..]).unwrap();
    assert_eq!(member1_user.threads[0].state, THREAD_STATE_GROUP_ACCEPTED);
    assert!(member1_user.threads[0].is_accepted());
    println!("  ✓ Member1 accepted group invite");

    // ========================================================================
    // Test 4: Send Second Message (uses non-zero nonce)
    // ========================================================================
    // Note: Sending group messages requires reading the sender's compressed
    // GroupKeyV1 account for membership verification. This is more complex
    // and would require additional test infrastructure for proof generation.
    // The create_group and accept_group_invite tests verify the core group
    // functionality. Full message sending would be tested in integration tests.

    println!("\n✅ All group tests passed!");
    println!("  - Group creation with owner's GroupKeyV1 ✓");
    println!("  - Group thread tracking in UserAccount ✓");
    println!("  - Group invite acceptance flow ✓");
}

// ============================================================================
// Instruction Helpers
// ============================================================================

/// Initialize a user account PDA with X25519 public key
pub async fn init_user(
    user: &Keypair,
    rpc: &mut LightProgramTest,
    x25519_pubkey: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&user.pubkey(), &program_id);

    let instruction_data = InitUserData {
        discriminator: InstructionType::InitUser,
        x25519_pubkey,
    };
    let inputs = InitUserData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(user.pubkey(), true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
    };

    rpc.create_and_send_transaction(&[instruction], &user.pubkey(), &[user])
        .await?;
    Ok(())
}

/// Accept a thread for a different user (funded by payer)
pub async fn accept_thread_for(
    _funder: &Keypair,
    user: &Keypair,
    rpc: &mut LightProgramTest,
    thread_id: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _bump) = get_user_pda(&user.pubkey(), &program_id);

    let instruction_data = AcceptThreadData {
        discriminator: InstructionType::AcceptThread,
        thread_id,
    };
    let inputs = AcceptThreadData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(user.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
    };

    // User signs
    rpc.create_and_send_transaction(&[instruction], &user.pubkey(), &[user])
        .await?;
    Ok(())
}

/// Send a DM message (creates compressed MsgV1 account)
/// Also adds thread to both sender and recipient UserAccounts
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
    let program_id: Pubkey = solcrypt_program::ID.into();

    // Get user PDAs
    let (sender_user_pda, _) = get_user_pda(&payer.pubkey(), &program_id);
    let (recipient_user_pda, _) = get_user_pda(&recipient, &program_id);

    let system_account_meta_config = SystemAccountMetaConfig::new(program_id);
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(payer.pubkey());
    packed_accounts.add_system_accounts(system_account_meta_config)?;

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

    let output_merkle_tree_index = packed_accounts.insert_or_get(*merkle_tree_pubkey);
    let packed_address_tree_info = rpc_result
        .pack_tree_infos(&mut packed_accounts)
        .address_trees[0];
    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build final account list:
    // [0] = signer (from light_accounts[0])
    // [1] = sender_user_pda
    // [2] = recipient_user_pda
    // [3] = system_program
    // [4..] = Light Protocol accounts (light_accounts[1..])
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(sender_user_pda, false),
        AccountMeta::new(recipient_user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    let instruction_data = SendDmMessageData {
        discriminator: InstructionType::SendDmMessage,
        proof: rpc_result.proof.into(),
        address_tree_info: packed_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        thread_id,
        recipient: recipient.to_bytes().into(),
        iv,
        ciphertext,
        nonce,
    };
    let inputs = SendDmMessageData::serialize(&instruction_data).unwrap();

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
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

    let instruction_data = AddThreadData {
        discriminator: InstructionType::AddThread,
        thread_id,
        state,
    };
    let inputs = AddThreadData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
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

    let instruction_data = AcceptThreadData {
        discriminator: InstructionType::AcceptThread,
        thread_id,
    };
    let inputs = AcceptThreadData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
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

    let instruction_data = RemoveThreadData {
        discriminator: InstructionType::RemoveThread,
        thread_id,
    };
    let inputs = RemoveThreadData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

// ============================================================================
// Group Instruction Helpers
// ============================================================================

/// Create a new group (owner creates GroupAccount PDA + owner's GroupKeyV1)
pub async fn create_group(
    payer: &Keypair,
    rpc: &mut LightProgramTest,
    merkle_tree_pubkey: &Pubkey,
    address_tree_pubkey: Pubkey,
    owner_key_address: [u8; 32],
    group_id: [u8; 32],
    encrypted_aes_key: [u8; 48],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();

    // Get PDAs
    let (user_pda, _) = get_user_pda(&payer.pubkey(), &program_id);
    let (group_pda, _) = get_group_pda(&group_id, &program_id);

    let system_account_meta_config = SystemAccountMetaConfig::new(program_id);
    let mut packed_accounts = PackedAccounts::default();
    packed_accounts.add_pre_accounts_signer(payer.pubkey());
    packed_accounts.add_system_accounts(system_account_meta_config)?;

    let rpc_result = rpc
        .get_validity_proof(
            vec![],
            vec![AddressWithTree {
                address: owner_key_address,
                tree: address_tree_pubkey,
            }],
            None,
        )
        .await?
        .value;

    let output_merkle_tree_index = packed_accounts.insert_or_get(*merkle_tree_pubkey);
    let packed_address_tree_info = rpc_result
        .pack_tree_infos(&mut packed_accounts)
        .address_trees[0];
    let (light_accounts, _, _) = packed_accounts.to_account_metas();

    // Build account list:
    // [0] = signer
    // [1] = user_pda
    // [2] = group_pda
    // [3] = system_program
    // [4..] = Light Protocol accounts
    let mut accounts = vec![
        light_accounts[0].clone(), // signer
        AccountMeta::new(user_pda, false),
        AccountMeta::new(group_pda, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];
    accounts.extend(light_accounts[1..].iter().cloned());

    let instruction_data = CreateGroupData {
        discriminator: InstructionType::CreateGroup,
        proof: rpc_result.proof.into(),
        address_tree_info: packed_address_tree_info.into(),
        output_state_tree_index: output_merkle_tree_index,
        group_id,
        encrypted_aes_key,
    };
    let inputs = CreateGroupData::serialize(&instruction_data).unwrap();

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
    };

    rpc.create_and_send_transaction(&[instruction], &payer.pubkey(), &[payer])
        .await?;
    Ok(())
}

/// Accept a group invitation
pub async fn accept_group_invite(
    user: &Keypair,
    rpc: &mut LightProgramTest,
    group_id: [u8; 32],
) -> Result<(), RpcError> {
    let program_id: Pubkey = solcrypt_program::ID.into();
    let (user_pda, _) = get_user_pda(&user.pubkey(), &program_id);

    let instruction_data = AcceptGroupInviteData {
        discriminator: InstructionType::AcceptGroupInvite,
        group_id,
    };
    let inputs = AcceptGroupInviteData::serialize(&instruction_data).unwrap();

    let accounts = vec![
        AccountMeta::new(user.pubkey(), true),
        AccountMeta::new(user_pda, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data: inputs,
    };

    rpc.create_and_send_transaction(&[instruction], &user.pubkey(), &[user])
        .await?;
    Ok(())
}
