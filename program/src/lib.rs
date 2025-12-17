#![allow(unexpected_cfgs)]

mod constants;
mod error;
mod instruction;
mod processor;
mod state;
mod types;

// Re-export public API
pub use constants::*;
pub use error::*;
pub use instruction::*;
pub use processor::{get_user_pda, to_custom_error, to_custom_error_u32};
pub use state::*;
pub use types::*;

#[cfg(feature = "bpf-entrypoint")]
mod entrypoint {
    use borsh::BorshDeserialize;
    use pinocchio::{
        ProgramResult, account_info::AccountInfo, entrypoint, program_error::ProgramError,
    };

    use crate::instruction::AcceptThreadData;
    use crate::instruction::AddThreadData;
    use crate::instruction::InitUserData;
    use crate::instruction::InstructionType;
    use crate::instruction::RemoveThreadData;
    use crate::instruction::SendDmMessageData;
    use crate::processor;

    entrypoint!(process_instruction);

    // ============================================================================
    // Entrypoint & Instruction Routing
    // ============================================================================

    pub fn process_instruction(
        program_id: &pinocchio::pubkey::Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if program_id != &pinocchio::pubkey::Pubkey::from(crate::ID) {
            return Err(ProgramError::IncorrectProgramId);
        }
        if instruction_data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let discriminator = InstructionType::try_from(instruction_data[0])
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        match discriminator {
            InstructionType::SendDmMessage => {
                let ix_data = SendDmMessageData::try_from_slice(&instruction_data[..])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                processor::send_dm_message(accounts, ix_data)
            }
            InstructionType::InitUser => {
                let ix_data = InitUserData::try_from_slice(&instruction_data[..])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                processor::init_user(accounts, ix_data)
            }
            InstructionType::AddThread => {
                let ix_data = AddThreadData::try_from_slice(&instruction_data[..])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                processor::add_thread(accounts, ix_data)
            }
            InstructionType::AcceptThread => {
                let ix_data = AcceptThreadData::try_from_slice(&instruction_data[..])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                processor::accept_thread(accounts, ix_data)
            }
            InstructionType::RemoveThread => {
                let ix_data = RemoveThreadData::try_from_slice(&instruction_data[..])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                processor::remove_thread(accounts, ix_data)
            }
        }
    }
}
