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
    use core::mem::MaybeUninit;

    use pinocchio::{
        ProgramResult, account_info::AccountInfo, entrypoint, program_error::ProgramError,
    };
    use wincode::Deserialize;

    use crate::instruction::AcceptThreadData;
    use crate::instruction::AddThreadData;
    use crate::instruction::InitUserData;
    use crate::instruction::InstructionType;
    use crate::instruction::RemoveThreadData;
    use crate::instruction::SendDmMessageData;
    use crate::processor;

    entrypoint!(process_instruction);

    /// Deserialize directly into heap memory, avoiding stack allocation of large structs.
    ///
    /// # Safety
    /// Safe because `deserialize_into` fully initializes the memory before we call `assume_init`.
    #[inline(never)]
    fn deserialize_to_heap<'a, T: Deserialize<'a, Dst = T>>(
        data: &'a [u8],
    ) -> Result<Box<T>, ProgramError> {
        let mut boxed = Box::new(MaybeUninit::<T>::uninit());
        T::deserialize_into(data, &mut *boxed).map_err(|_| ProgramError::InvalidInstructionData)?;
        // SAFETY: deserialize_into succeeded, so memory is fully initialized
        Ok(unsafe { boxed.assume_init() })
    }

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
                let ix_data = deserialize_to_heap::<SendDmMessageData>(instruction_data)?;
                processor::send_dm_message(accounts, ix_data)
            }
            InstructionType::InitUser => {
                let ix_data = deserialize_to_heap::<InitUserData>(instruction_data)?;
                processor::init_user(accounts, ix_data)
            }
            InstructionType::AddThread => {
                let ix_data = deserialize_to_heap::<AddThreadData>(instruction_data)?;
                processor::add_thread(accounts, ix_data)
            }
            InstructionType::AcceptThread => {
                let ix_data = deserialize_to_heap::<AcceptThreadData>(instruction_data)?;
                processor::accept_thread(accounts, ix_data)
            }
            InstructionType::RemoveThread => {
                let ix_data = deserialize_to_heap::<RemoveThreadData>(instruction_data)?;
                processor::remove_thread(accounts, ix_data)
            }
        }
    }
}
