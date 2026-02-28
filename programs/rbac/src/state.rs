use anchor_lang::prelude::*;
use crate::errors::RbacError;

pub const MAX_ORG_NAME_LEN: usize = 32;

/// Well-known permission index that grants the ability to assign/revoke roles.
pub const MANAGE_ROLES_PERMISSION_INDEX: u32 = 3;
pub const MAX_ROLE_NAME_LEN: usize = 32;
pub const MAX_ROLE_DESC_LEN: usize = 128;
pub const MAX_PERMISSION_NAME_LEN: usize = 32;
pub const MAX_PERMISSION_DESC_LEN: usize = 128;
pub const MAX_RESOURCE_TITLE_LEN: usize = 64;

/// Roles 0..15 live in chunk 0, 16..31 in chunk 1, etc.
pub const ROLES_PER_CHUNK: usize = 16;
/// Permissions 0..31 live in chunk 0, 32..63 in chunk 1, etc.
pub const PERMS_PER_CHUNK: usize = 32;

// ---------------------------------------------------------------------------
// Organization state machine
// ---------------------------------------------------------------------------

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum OrgState {
    Idle,
    Updating,
    Recomputing,
}

impl Default for OrgState {
    fn default() -> Self {
        OrgState::Idle
    }
}

// ---------------------------------------------------------------------------
// Embedded structs (not standalone accounts)
// ---------------------------------------------------------------------------

/// A single role entry stored inside a RoleChunk.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default)]
pub struct RoleEntry {
    pub topo_index: u32,
    /// Bumped on every structural change (permission/child adds/removes, recompute).
    pub version: u64,
    pub name: String,
    pub description: String,
    pub direct_permissions: Vec<u8>,
    pub effective_permissions: Vec<u8>,
    /// Children stored as topo_indices (NOT Pubkeys).
    pub children: Vec<u32>,
    pub active: bool,
}

impl RoleEntry {
    /// Borsh-serialized byte count for this entry.
    pub fn serialized_size(&self) -> usize {
        4  // topo_index
        + 8  // version
        + (4 + self.name.len())
        + (4 + self.description.len())
        + (4 + self.direct_permissions.len())
        + (4 + self.effective_permissions.len())
        + (4 + self.children.len() * 4)
        + 1  // active
    }
}

/// A single permission entry stored inside a PermChunk.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default)]
pub struct PermEntry {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub created_by: Pubkey,
    pub active: bool,
}

impl PermEntry {
    pub fn serialized_size(&self) -> usize {
        4  // index
        + (4 + self.name.len())
        + (4 + self.description.len())
        + 32  // created_by
        + 1   // active
    }
}

/// Reference from a UserAccount to a role, with per-role staleness tracking.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RoleRef {
    pub topo_index: u32,
    /// Version of the role at the time the user's permissions were last computed.
    pub last_seen_version: u64,
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[account]
pub struct Organization {
    pub super_admin: Pubkey,
    pub name: String,
    pub member_count: u64,
    pub next_permission_index: u32,
    pub role_count: u32,
    pub permissions_version: u64,
    pub state: OrgState,
    pub bump: u8,
}

impl Organization {
    pub const FIXED_SIZE: usize = 8  // discriminator
        + 32                          // super_admin
        + (4 + MAX_ORG_NAME_LEN)     // name
        + 8                           // member_count
        + 4                           // next_permission_index
        + 4                           // role_count
        + 8                           // permissions_version
        + 1 + 0                       // OrgState enum (1-byte tag, no data)
        + 1;                          // bump
}

/// Holds up to ROLES_PER_CHUNK role entries. PDA: ["role_chunk", org, chunk_index_le4].
#[account]
pub struct RoleChunk {
    pub organization: Pubkey,
    pub chunk_index: u32,
    pub bump: u8,
    pub entries: Vec<RoleEntry>,
}

impl RoleChunk {
    /// Minimum allocation for an empty chunk (discriminator + fixed fields + empty vec len).
    pub const BASE_SIZE: usize = 8   // discriminator
        + 32  // organization
        + 4   // chunk_index
        + 1   // bump
        + 4;  // entries vec length prefix
}

/// Holds up to PERMS_PER_CHUNK permission entries. PDA: ["perm_chunk", org, chunk_index_le4].
#[account]
pub struct PermChunk {
    pub organization: Pubkey,
    pub chunk_index: u32,
    pub bump: u8,
    pub entries: Vec<PermEntry>,
}

impl PermChunk {
    pub const BASE_SIZE: usize = 8   // discriminator
        + 32  // organization
        + 4   // chunk_index
        + 1   // bump
        + 4;  // entries vec length prefix
}

#[account]
pub struct UserAccount {
    pub organization: Pubkey,
    pub user: Pubkey,
    /// Each RoleRef is 12 bytes (4 topo_index + 8 last_seen_version).
    pub assigned_roles: Vec<RoleRef>,
    pub direct_permissions: Vec<u8>,
    pub effective_permissions: Vec<u8>,
    pub cached_version: u64,
    pub bump: u8,
}

impl UserAccount {
    pub const BASE_SIZE: usize = 8   // discriminator
        + 32                          // organization
        + 32                          // user
        + 4                           // assigned_roles vec len
        + 4                           // direct_permissions vec len
        + 4                           // effective_permissions vec len
        + 8                           // cached_version
        + 1;                          // bump

    pub fn current_size(&self) -> usize {
        Self::BASE_SIZE
            + self.assigned_roles.len() * 12  // RoleRef: 4 (topo_index) + 8 (last_seen_version)
            + self.direct_permissions.len()
            + self.effective_permissions.len()
    }
}

/// Fixed-size hot-path permission cache for a user.
/// PDA: ["user_perm_cache", org_key, user_key]
#[account]
pub struct UserPermCache {
    pub organization: Pubkey,            // 32
    pub user: Pubkey,                    // 32
    pub effective_permissions: [u8; 32], // 32  — 256 perms max, fixed
    pub effective_roles: [u8; 32],       // 32  — 256 roles max, bitmask
    pub permissions_version: u64,        // 8
    pub bump: u8,                        // 1
}

impl UserPermCache {
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 8 + 1; // 145 bytes, always fixed
}

#[account]
pub struct Resource {
    pub organization: Pubkey,
    pub creator: Pubkey,
    pub title: String,
    pub resource_id: u64,
    pub created_at: i64,
    pub bump: u8,
}

impl Resource {
    pub const SIZE: usize = 8 + 32 + 32 + (4 + MAX_RESOURCE_TITLE_LEN) + 8 + 8 + 1;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct AccessVerified {
    pub organization: Pubkey,
    pub user: Pubkey,
    pub has_access: bool,
}

#[event]
pub struct RoleChanged {
    pub organization: Pubkey,
    pub role_index: u32,
    pub role_name: String,
}

#[event]
pub struct OrgCreated {
    pub organization: Pubkey,
    pub name: String,
    pub super_admin: Pubkey,
}

#[event]
pub struct RoleCreated {
    pub organization: Pubkey,
    pub topo_index: u32,
    pub name: String,
}

#[event]
pub struct RoleDeleted {
    pub organization: Pubkey,
    pub role_index: u32,
    pub name: String,
}

#[event]
pub struct PermissionCreated {
    pub organization: Pubkey,
    pub perm_index: u32,
    pub name: String,
}

#[event]
pub struct PermissionDeleted {
    pub organization: Pubkey,
    pub perm_index: u32,
}

#[event]
pub struct RolePermissionAdded {
    pub organization: Pubkey,
    pub role_index: u32,
    pub permission_index: u32,
}

#[event]
pub struct RolePermissionRemoved {
    pub organization: Pubkey,
    pub role_index: u32,
    pub permission_index: u32,
}

#[event]
pub struct ChildRoleAdded {
    pub organization: Pubkey,
    pub parent_index: u32,
    pub child_index: u32,
}

#[event]
pub struct ChildRoleRemoved {
    pub organization: Pubkey,
    pub parent_index: u32,
    pub child_index: u32,
}

#[event]
pub struct UserCreated {
    pub organization: Pubkey,
    pub user: Pubkey,
}

#[event]
pub struct RoleAssigned {
    pub organization: Pubkey,
    pub user: Pubkey,
    pub role_index: u32,
}

#[event]
pub struct RoleRevoked {
    pub organization: Pubkey,
    pub user: Pubkey,
    pub role_index: u32,
}

#[event]
pub struct UserPermissionGranted {
    pub organization: Pubkey,
    pub user: Pubkey,
    pub permission_index: u32,
}

#[event]
pub struct UserPermissionRevoked {
    pub organization: Pubkey,
    pub user: Pubkey,
    pub permission_index: u32,
}

// ---------------------------------------------------------------------------
// Bitmask helpers
// ---------------------------------------------------------------------------

pub fn has_bit(bitmask: &[u8], index: u32) -> bool {
    let byte_pos = index as usize / 8;
    let bit_pos = index as usize % 8;
    byte_pos < bitmask.len() && (bitmask[byte_pos] & (1 << bit_pos) != 0)
}

pub fn set_bit(bitmask: &mut Vec<u8>, index: u32) {
    let byte_pos = index as usize / 8;
    let bit_pos = index as usize % 8;
    if byte_pos >= bitmask.len() {
        bitmask.resize(byte_pos + 1, 0);
    }
    bitmask[byte_pos] |= 1 << bit_pos;
}

pub fn clear_bit(bitmask: &mut Vec<u8>, index: u32) {
    let byte_pos = index as usize / 8;
    if byte_pos < bitmask.len() {
        let bit_pos = index as usize % 8;
        bitmask[byte_pos] &= !(1 << bit_pos);
    }
}

pub fn bitmask_union(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u8; max_len];
    for (i, byte) in a.iter().  enumerate() {
        result[i] |= byte;
    }
    for (i, byte) in b.iter().enumerate() {
        result[i] |= byte;
    }
    result
}

/// Returns the minimum number of bytes needed for a bitmask to hold `index`.
pub fn bitmask_bytes_for(index: u32) -> usize {
    (index as usize / 8) + 1
}

/// Set a bit in a fixed-size byte slice (noop if index out of bounds).
pub fn set_bit_arr(bitmask: &mut [u8], index: u32) {
    let byte_pos = index as usize / 8;
    let bit_pos = index as usize % 8;
    if byte_pos < bitmask.len() {
        bitmask[byte_pos] |= 1 << bit_pos;
    }
}

/// Clear a bit in a fixed-size byte slice (noop if index out of bounds).
pub fn clear_bit_arr(bitmask: &mut [u8], index: u32) {
    let byte_pos = index as usize / 8;
    if byte_pos < bitmask.len() {
        let bit_pos = index as usize % 8;
        bitmask[byte_pos] &= !(1 << bit_pos);
    }
}

/// OR src (Vec) into dest (fixed [u8;32]) in-place.
pub fn bitmask_union_into(dest: &mut [u8], src: &[u8]) {
    for (i, byte) in src.iter().enumerate() {
        if i < dest.len() {
            dest[i] |= byte;
        }
    }
}

/// Zero dest then copy src (Vec) into it (truncating to 32 bytes).
pub fn copy_to_fixed(dest: &mut [u8; 32], src: &[u8]) {
    dest.fill(0);
    let len = src.len().min(32);
    dest[..len].copy_from_slice(&src[..len]);
}

// ---------------------------------------------------------------------------
// Chunk lookup helper (used by multiple instructions)
// ---------------------------------------------------------------------------

/// Find and deserialize a RoleChunk from a slice of AccountInfos, verifying its PDA.
///
/// Scans `accounts` for an account whose deserialized `chunk_index` matches
/// `chunk_idx` and whose key matches the derived PDA (using the stored bump).
pub fn find_role_chunk_in_accounts<'info>(
    accounts: &[AccountInfo<'info>],
    org_key: &Pubkey,
    chunk_idx: u32,
    program_id: &Pubkey,
) -> Result<RoleChunk> {
    let chunk_idx_bytes = chunk_idx.to_le_bytes();
    for ai in accounts.iter() {
        if ai.owner != program_id {
            continue;
        }
        let data = match ai.try_borrow_data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.len() < RoleChunk::BASE_SIZE {
            continue;
        }
        match RoleChunk::try_deserialize(&mut &data[..]) {
            Ok(chunk) if chunk.organization == *org_key && chunk.chunk_index == chunk_idx => {
                // Verify PDA using stored bump (no search loop needed).
                let seeds: &[&[u8]] = &[
                    b"role_chunk",
                    org_key.as_ref(),
                    &chunk_idx_bytes,
                    &[chunk.bump],
                ];
                if let Ok(derived) = Pubkey::create_program_address(seeds, program_id) {
                    if derived == ai.key() {
                        return Ok(chunk);
                    }
                }
            }
            _ => continue,
        }
    }
    err!(RbacError::ChunkNotFound)
}
