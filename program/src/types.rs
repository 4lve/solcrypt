use codama::CodamaType;
use light_sdk_pinocchio::instruction::{
    CompressedProof, PackedAddressTreeInfo, PackedStateTreeInfo, ValidityProof,
    account_meta::CompressedAccountMeta,
};
use wincode::{SchemaRead, SchemaWrite};

// ============================================================================
// Codama Wrapper Types
// ============================================================================

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct CompressedProofCodama {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl From<CompressedProofCodama> for CompressedProof {
    fn from(value: CompressedProofCodama) -> Self {
        CompressedProof {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

impl From<CompressedProof> for CompressedProofCodama {
    fn from(value: CompressedProof) -> Self {
        CompressedProofCodama {
            a: value.a,
            b: value.b,
            c: value.c,
        }
    }
}

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct ValidityProofCodama(pub Option<CompressedProofCodama>);

impl From<ValidityProofCodama> for ValidityProof {
    fn from(value: ValidityProofCodama) -> Self {
        ValidityProof(value.0.map(CompressedProof::from))
    }
}

impl From<ValidityProof> for ValidityProofCodama {
    fn from(value: ValidityProof) -> Self {
        ValidityProofCodama(value.0.map(CompressedProofCodama::from))
    }
}

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct PackedAddressTreeInfoCodama {
    pub address_merkle_tree_pubkey_index: u8,
    pub address_queue_pubkey_index: u8,
    pub root_index: u16,
}

impl From<PackedAddressTreeInfoCodama> for PackedAddressTreeInfo {
    fn from(value: PackedAddressTreeInfoCodama) -> Self {
        PackedAddressTreeInfo {
            address_merkle_tree_pubkey_index: value.address_merkle_tree_pubkey_index,
            address_queue_pubkey_index: value.address_queue_pubkey_index,
            root_index: value.root_index,
        }
    }
}

impl From<PackedAddressTreeInfo> for PackedAddressTreeInfoCodama {
    fn from(value: PackedAddressTreeInfo) -> Self {
        PackedAddressTreeInfoCodama {
            address_merkle_tree_pubkey_index: value.address_merkle_tree_pubkey_index,
            address_queue_pubkey_index: value.address_queue_pubkey_index,
            root_index: value.root_index,
        }
    }
}

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct PackedStateTreeInfoCodama {
    pub root_index: u16,
    pub prove_by_index: bool,
    pub merkle_tree_pubkey_index: u8,
    pub queue_pubkey_index: u8,
    pub leaf_index: u32,
}

impl From<PackedStateTreeInfoCodama> for PackedStateTreeInfo {
    fn from(value: PackedStateTreeInfoCodama) -> Self {
        PackedStateTreeInfo {
            root_index: value.root_index,
            prove_by_index: value.prove_by_index,
            merkle_tree_pubkey_index: value.merkle_tree_pubkey_index,
            queue_pubkey_index: value.queue_pubkey_index,
            leaf_index: value.leaf_index,
        }
    }
}

impl From<PackedStateTreeInfo> for PackedStateTreeInfoCodama {
    fn from(value: PackedStateTreeInfo) -> Self {
        PackedStateTreeInfoCodama {
            root_index: value.root_index,
            prove_by_index: value.prove_by_index,
            merkle_tree_pubkey_index: value.merkle_tree_pubkey_index,
            queue_pubkey_index: value.queue_pubkey_index,
            leaf_index: value.leaf_index,
        }
    }
}

#[derive(Debug, Clone, SchemaWrite, SchemaRead, CodamaType)]
pub struct CompressedAccountMetaCodama {
    pub tree_info: PackedStateTreeInfoCodama,
    pub address: [u8; 32],
    pub output_state_tree_index: u8,
}

impl From<CompressedAccountMetaCodama> for CompressedAccountMeta {
    fn from(value: CompressedAccountMetaCodama) -> Self {
        CompressedAccountMeta {
            tree_info: value.tree_info.into(),
            address: value.address,
            output_state_tree_index: value.output_state_tree_index,
        }
    }
}

impl From<CompressedAccountMeta> for CompressedAccountMetaCodama {
    fn from(value: CompressedAccountMeta) -> Self {
        CompressedAccountMetaCodama {
            tree_info: value.tree_info.into(),
            address: value.address,
            output_state_tree_index: value.output_state_tree_index,
        }
    }
}

/// Message content enum - serialized before encryption.
/// This is a client-side protocol; the program only sees opaque ciphertext bytes.
#[derive(Debug, Clone, SchemaWrite, SchemaRead, PartialEq, CodamaType)]
#[wincode(tag_encoding = "u8")]
#[repr(u8)]
pub enum ClientSideMessage {
    Text(String),
    Image(String),
}
