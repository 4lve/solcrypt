use codama::CodamaErrors;
use pinocchio::program_error::ProgramError;

// ============================================================================
// Error Definitions
// ============================================================================

#[derive(Debug, Clone, CodamaErrors)]
pub enum SolcryptError {
    #[codama(error("The provided signer does not match the expected authority"))]
    Unauthorized,
    #[codama(error("Thread already exists in the user's thread list"))]
    ThreadAlreadyExists,
    #[codama(error("Thread not found in the user's thread list"))]
    ThreadNotFound,
    #[codama(error("Thread has already been accepted"))]
    ThreadAlreadyAccepted,
    #[codama(error("Message ciphertext exceeds maximum allowed size"))]
    MessageTooLarge,
    #[codama(error("PDA derivation does not match expected address"))]
    InvalidPda,
    #[codama(error("User account already initialized"))]
    UserAlreadyInitialized,
    #[codama(error("Sender has not initialized their user account"))]
    UserNotInitialized,
    #[codama(error("Recipient has not initialized their user account"))]
    RecipientNotInitialized,
    #[codama(error("First message in a thread must use nonce 0"))]
    FirstMessageMustUseNonceZero,
    #[codama(error("Subsequent messages must not use nonce 0"))]
    SubsequentMessageCannotUseNonceZero,
    // Group chat errors
    #[codama(error("Only the group owner can perform this action"))]
    NotGroupOwner,
    #[codama(error("Only group admins or owner can perform this action"))]
    NotGroupAdmin,
    #[codama(error("User is not a member of this group"))]
    NotGroupMember,
    #[codama(error("Cannot remove a member with equal or higher role"))]
    CannotRemoveHigherRole,
    #[codama(error("Group owner cannot leave; must transfer ownership first"))]
    OwnerCannotLeave,
    #[codama(error("Group with this ID already exists"))]
    GroupAlreadyExists,
    #[codama(error("User is already a member of this group"))]
    MemberAlreadyInGroup,
    #[codama(error("No pending invitation found for this group"))]
    InvitationNotFound,
    #[codama(error("Invalid role value provided"))]
    InvalidRole,
    #[codama(error("Key version does not match current group key version"))]
    KeyVersionMismatch,
}

impl From<SolcryptError> for ProgramError {
    fn from(e: SolcryptError) -> Self {
        match e {
            SolcryptError::Unauthorized => ProgramError::Custom(1),
            SolcryptError::ThreadAlreadyExists => ProgramError::Custom(2),
            SolcryptError::ThreadNotFound => ProgramError::Custom(3),
            SolcryptError::ThreadAlreadyAccepted => ProgramError::Custom(4),
            SolcryptError::MessageTooLarge => ProgramError::Custom(5),
            SolcryptError::InvalidPda => ProgramError::Custom(6),
            SolcryptError::UserAlreadyInitialized => ProgramError::Custom(7),
            SolcryptError::UserNotInitialized => ProgramError::Custom(8),
            SolcryptError::RecipientNotInitialized => ProgramError::Custom(9),
            SolcryptError::FirstMessageMustUseNonceZero => ProgramError::Custom(10),
            SolcryptError::SubsequentMessageCannotUseNonceZero => ProgramError::Custom(11),
            // Group chat errors
            SolcryptError::NotGroupOwner => ProgramError::Custom(12),
            SolcryptError::NotGroupAdmin => ProgramError::Custom(13),
            SolcryptError::NotGroupMember => ProgramError::Custom(14),
            SolcryptError::CannotRemoveHigherRole => ProgramError::Custom(15),
            SolcryptError::OwnerCannotLeave => ProgramError::Custom(16),
            SolcryptError::GroupAlreadyExists => ProgramError::Custom(17),
            SolcryptError::MemberAlreadyInGroup => ProgramError::Custom(18),
            SolcryptError::InvitationNotFound => ProgramError::Custom(19),
            SolcryptError::InvalidRole => ProgramError::Custom(20),
            SolcryptError::KeyVersionMismatch => ProgramError::Custom(21),
        }
    }
}
