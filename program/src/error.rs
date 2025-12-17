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
        }
    }
}
