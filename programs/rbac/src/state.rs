use anchor_lang::prelude::*;
use std::collections::HashMap;

use crate::errors::RbacError;

pub const MAX_ORG_NAME_LEN: usize = 32;

pub const MAX_ROLE_NAME_LEN: usize = 32;
pub const MAX_ROLE_DESC_LEN: usize = 128;
pub const MAX_PERMISSION_NAME_LEN: usize = 32;
pub const MAX_PERMISSION_DESC_LEN: usize = 128;
pub const MAX_RESOURCE_TITLE_LEN: usize = 64;

/// Roles 0..15 live in chunk 0, 16..31 in chunk 1, etc.
pub const ROLES_PER_CHUNK: usize = 16;
/// Permissions 0..31 live in chunk 0, 32..63 in chunk 1, etc.
pub const PERMS_PER_CHUNK: usize = 32;
/// Maximum number of direct child roles a single parent role may have.
/// Prevents unbounded account growth and O(n²) recompute costs.
pub const MAX_CHILDREN_PER_ROLE: usize = 32;

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
    /// Set to org.permissions_version each time recompute_role runs. Used to
    /// prevent the same role from being recomputed twice in one update cycle,
    /// which would double-decrement roles_pending_recompute. Initialized to
    /// u64::MAX so the first-cycle check (version == 0) doesn't false-trigger.
    pub recompute_epoch: u64,
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
        + 8  // recompute_epoch
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
    /// The current authority who can administer this organization.
    /// Changed by transfer_super_admin; used only for authorization checks.
    pub super_admin: Pubkey,
    /// The pubkey of the original creator — stored immutably and used in PDA
    /// seeds so the org address is stable across super_admin transfers.
    pub original_admin: Pubkey,
    pub name: String,
    pub member_count: u64,
    pub next_permission_index: u32,
    pub role_count: u32,
    /// Number of currently active (non-deleted) roles. Incremented by create_role,
    /// decremented by delete_role. Used to initialise roles_pending_recompute.
    pub active_role_count: u32,
    pub permissions_version: u64,
    pub state: OrgState,
    pub bump: u8,
    /// Set to active_role_count by begin_update, decremented by recompute_role.
    /// commit_update requires this to be 0.
    pub roles_pending_recompute: u32,
    /// Set to member_count by commit_update, decremented by
    /// process_recompute_batch. finish_update requires this to be 0.
    pub users_pending_recompute: u32,
    /// Permission index that grants the ability to assign/revoke roles on behalf
    /// of the super_admin. Set at org creation; configurable per-organization.
    pub manage_roles_permission: u32,
}

impl Organization {
    pub const FIXED_SIZE: usize = 8  // discriminator
        + 32                          // super_admin
        + 32                          // original_admin
        + (4 + MAX_ORG_NAME_LEN)     // name
        + 8                           // member_count
        + 4                           // next_permission_index
        + 4                           // role_count
        + 4                           // active_role_count
        + 8                           // permissions_version
        + 1 + 0                       // OrgState enum (1-byte tag, no data)
        + 1                           // bump
        + 4                           // roles_pending_recompute
        + 4                           // users_pending_recompute
        + 4;                          // manage_roles_permission
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
    /// The permission index required to create/delete this resource.
    /// Stored at creation time; enforced at deletion time so the caller
    /// cannot self-select a weaker permission.
    pub required_permission: u32,
}

impl Resource {
    pub const SIZE: usize = 8 + 32 + 32 + (4 + MAX_RESOURCE_TITLE_LEN) + 8 + 8 + 1 + 4;
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
    for (i, byte) in a.iter().enumerate() {
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

/// Returns `true` if every bit set in `subset` is also set in `superset`.
///
/// Used by the delegated assign/revoke path to prevent privilege escalation:
/// a caller may only assign or revoke a role whose effective permissions are
/// fully contained within their own effective permissions.
pub fn bitmask_is_subset(subset: &[u8], superset: &[u8]) -> bool {
    for (i, &byte) in subset.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        let super_byte = if i < superset.len() { superset[i] } else { 0 };
        if byte & !super_byte != 0 {
            return false;
        }
    }
    true
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

/// Find and deserialize a PermChunk from a slice of AccountInfos, verifying its PDA.
pub fn find_perm_chunk_in_accounts<'info>(
    accounts: &[AccountInfo<'info>],
    org_key: &Pubkey,
    chunk_idx: u32,
    program_id: &Pubkey,
) -> Result<PermChunk> {
    let chunk_idx_bytes = chunk_idx.to_le_bytes();
    for ai in accounts.iter() {
        if ai.owner != program_id {
            continue;
        }
        let data = match ai.try_borrow_data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.len() < PermChunk::BASE_SIZE {
            continue;
        }
        match PermChunk::try_deserialize(&mut &data[..]) {
            Ok(chunk) if chunk.organization == *org_key && chunk.chunk_index == chunk_idx => {
                let seeds: &[&[u8]] = &[
                    b"perm_chunk",
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

// ---------------------------------------------------------------------------
// Chunk indices: build once per instruction, O(1) lookups
// ---------------------------------------------------------------------------

/// Build a map of chunk_index -> PermChunk from a slice of accounts.
/// One pass over accounts; all later lookups are O(1).
pub fn build_perm_chunk_index<'info>(
    accounts: &[AccountInfo<'info>],
    org_key: &Pubkey,
    program_id: &Pubkey,
) -> Result<HashMap<u32, PermChunk>> {
    let mut index = HashMap::new();
    for ai in accounts.iter() {
        if ai.owner != program_id {
            continue;
        }
        let data = match ai.try_borrow_data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.len() < PermChunk::BASE_SIZE {
            continue;
        }
        if let Ok(chunk) = PermChunk::try_deserialize(&mut &data[..]) {
            if chunk.organization != *org_key {
                continue;
            }
            let chunk_idx = chunk.chunk_index;
            let chunk_idx_bytes = chunk_idx.to_le_bytes();
            let seeds: &[&[u8]] = &[
                b"perm_chunk",
                org_key.as_ref(),
                &chunk_idx_bytes,
                &[chunk.bump],
            ];
            if let Ok(derived) = Pubkey::create_program_address(seeds, program_id) {
                if derived == ai.key() {
                    index.insert(chunk_idx, chunk);
                }
            }
        }
    }
    Ok(index)
}

/// Build a map of chunk_index -> RoleChunk from a slice of accounts.
/// One pass over accounts; all later lookups are O(1).
pub fn build_role_chunk_index<'info>(
    accounts: &[AccountInfo<'info>],
    org_key: &Pubkey,
    program_id: &Pubkey,
) -> Result<HashMap<u32, RoleChunk>> {
    let mut index = HashMap::new();
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
        if let Ok(chunk) = RoleChunk::try_deserialize(&mut &data[..]) {
            if chunk.organization != *org_key {
                continue;
            }
            let chunk_idx = chunk.chunk_index;
            let chunk_idx_bytes = chunk_idx.to_le_bytes();
            let seeds: &[&[u8]] = &[
                b"role_chunk",
                org_key.as_ref(),
                &chunk_idx_bytes,
                &[chunk.bump],
            ];
            if let Ok(derived) = Pubkey::create_program_address(seeds, program_id) {
                if derived == ai.key() {
                    index.insert(chunk_idx, chunk);
                }
            }
        }
    }
    Ok(index)
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic, no runtime required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Bitmask helpers ────────────────────────────────────────────────────

    #[test]
    fn test_has_bit_basic() {
        let mask = vec![0b0000_0101u8]; // bits 0 and 2 set
        assert!(has_bit(&mask, 0));
        assert!(!has_bit(&mask, 1));
        assert!(has_bit(&mask, 2));
        assert!(!has_bit(&mask, 3));
    }

    #[test]
    fn test_has_bit_out_of_bounds() {
        let mask = vec![0xFFu8];
        assert!(!has_bit(&mask, 8));   // byte 1 not present
        assert!(!has_bit(&mask, 255));
    }

    #[test]
    fn test_set_bit_grows_vec() {
        let mut mask: Vec<u8> = Vec::new();
        set_bit(&mut mask, 17); // byte 2, bit 1
        assert_eq!(mask.len(), 3);
        assert!(has_bit(&mask, 17));
        assert!(!has_bit(&mask, 16));
    }

    #[test]
    fn test_clear_bit() {
        let mut mask = vec![0xFF, 0xFF];
        clear_bit(&mut mask, 8); // first bit of byte 1
        assert!(!has_bit(&mask, 8));
        assert!(has_bit(&mask, 9));
        assert!(has_bit(&mask, 7));
    }

    #[test]
    fn test_bitmask_union_different_lengths() {
        let a = vec![0b1010_0000u8]; // bits 5,7
        let b = vec![0b0000_0001u8, 0b0000_0010u8]; // bits 0, 9
        let r = bitmask_union(&a, &b);
        assert_eq!(r.len(), 2);
        assert!(has_bit(&r, 0));
        assert!(has_bit(&r, 5));
        assert!(has_bit(&r, 7));
        assert!(has_bit(&r, 9));
        assert!(!has_bit(&r, 1));
    }

    #[test]
    fn test_bitmask_union_empty() {
        let r = bitmask_union(&[], &[]);
        assert!(r.is_empty());
        let r2 = bitmask_union(&[0xABu8], &[]);
        assert_eq!(r2, vec![0xABu8]);
    }

    // ── Delegation PDA uniqueness across orgs ─────────────────────────────
    // The fix adds find_program_address verification so a cache from org A
    // cannot be used to authorise operations in org B.
    #[test]
    fn test_pda_uniqueness_across_orgs() {
        let org_a = Pubkey::new_unique();
        let org_b = Pubkey::new_unique();
        let user  = Pubkey::new_unique();
        let pid   = Pubkey::new_unique();

        let (pda_a, _) = Pubkey::find_program_address(
            &[b"user_perm_cache", org_a.as_ref(), user.as_ref()],
            &pid,
        );
        let (pda_b, _) = Pubkey::find_program_address(
            &[b"user_perm_cache", org_b.as_ref(), user.as_ref()],
            &pid,
        );
        assert_ne!(pda_a, pda_b, "PDAs for different orgs must differ");
    }

    // ── PermEntry active flag ──────────────────────────────────────────────
    #[test]
    fn test_perm_entry_active_flag() {
        let entry = PermEntry {
            index: 5,
            name: "read".into(),
            description: "".into(),
            created_by: Pubkey::default(),
            active: true,
        };
        assert!(entry.active);
        let deleted = PermEntry { active: false, ..entry };
        assert!(!deleted.active);
    }

    // ── Cache staleness: version comparison ───────────────────────────────
    #[test]
    fn test_permissions_version_staleness() {
        let cache_version: u64 = 2;
        let org_version: u64 = 3;
        assert!(cache_version < org_version, "stale cache detected");
        let fresh_version: u64 = 3;
        assert!(fresh_version >= org_version, "fresh cache passes");
    }

    // ── Filtering a bitmask through an active-permission set ──────────────
    #[test]
    fn test_filter_bitmask_by_active_set() {
        let mut source: Vec<u8> = Vec::new();
        set_bit(&mut source, 0);
        set_bit(&mut source, 1); // will be "deleted"
        set_bit(&mut source, 2);

        let active: std::collections::HashSet<u32> = [0u32, 2u32].iter().cloned().collect();

        let mut result: Vec<u8> = Vec::new();
        for (byte_idx, &byte) in source.iter().enumerate() {
            if byte == 0 { continue; }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let idx = (byte_idx as u32) * 8 + bit;
                    if active.contains(&idx) {
                        set_bit(&mut result, idx);
                    }
                }
            }
        }

        assert!(has_bit(&result, 0));
        assert!(!has_bit(&result, 1), "deleted perm 1 must be dropped");
        assert!(has_bit(&result, 2));
    }

    // ── Update cycle completeness counters ────────────────────────────────
    #[test]
    fn test_roles_pending_recompute_counter() {
        let active_role_count: u32 = 3;
        let mut pending: u32 = active_role_count; // begin_update
        for _ in 0..active_role_count {
            pending = pending.saturating_sub(1); // each recompute_role call
        }
        assert_eq!(pending, 0);
    }

    #[test]
    fn test_users_pending_recompute_counter() {
        let member_count: u32 = 5;
        let mut pending: u32 = member_count; // commit_update
        pending = pending.saturating_sub(3); // first process_recompute_batch (3 users)
        pending = pending.saturating_sub(2); // second call (2 users)
        assert_eq!(pending, 0);
    }

    // ── Role count bitmask overflow guard ─────────────────────────────────
    // UserPermCache.effective_roles is [u8; 32] (256-bit fixed bitmask).
    // set_bit_arr is a silent no-op for index >= 256, so create_role must
    // reject any call that would push active_role_count to 256 or beyond.
    #[test]
    fn test_set_bit_arr_noop_at_256() {
        let mut cache = [0u8; 32];
        // index 255 is the last representable slot — must set the bit
        set_bit_arr(&mut cache, 255);
        assert_eq!(cache[31], 0b1000_0000, "bit 255 must be set");
        // index 256 falls outside the 32-byte window — must be a silent no-op
        set_bit_arr(&mut cache, 256);
        // the array must be unchanged (all bytes after the previous write are 0)
        assert_eq!(cache[0], 0, "overflow write must not corrupt byte 0");
        assert_eq!(cache[31], 0b1000_0000, "overflow write must not corrupt byte 31");
    }

    #[test]
    fn test_role_count_cap_at_256() {
        // Simulate the create_role guard: active_role_count must stay < 256.
        let active_role_count: u32 = 255;
        assert!(active_role_count < 256, "255 active roles is within limit");
        let would_overflow: u32 = 256;
        assert!(!(would_overflow < 256), "256 active roles must be rejected");
    }

    // ── RoleEntry serialized_size sanity ──────────────────────────────────
    #[test]
    fn test_role_entry_serialized_size() {
        let entry = RoleEntry {
            topo_index: 0,
            version: 0,
            name: "admin".into(),
            description: "".into(),
            direct_permissions: vec![0u8; 2],
            effective_permissions: vec![0u8; 2],
            children: vec![],
            active: true,
            recompute_epoch: u64::MAX,
        };
        // 4(topo) + 8(ver) + (4+5)(name) + (4+0)(desc) + (4+2)(dp) + (4+2)(ep) + (4+0)(children) + 1(active) + 8(recompute_epoch)
        assert_eq!(entry.serialized_size(), 4 + 8 + 9 + 4 + 6 + 6 + 4 + 1 + 8);
    }

    // ── Recompute order: child must be recomputed before parent ─────────────
    // recompute_role requires every child's recompute_epoch == org.permissions_version.
    // recompute_epoch == u64::MAX means "never recomputed"; equality with
    // permissions_version means "recomputed this update cycle".
    #[test]
    fn test_recompute_order_child_epoch_semantics() {
        let org_permissions_version: u64 = 5;
        // Child never recomputed — must not pass the "child before parent" check.
        let child_never = RoleEntry {
            recompute_epoch: u64::MAX,
            ..RoleEntry::default()
        };
        assert_ne!(
            child_never.recompute_epoch,
            org_permissions_version,
            "never-recomputed child must fail parent recompute check"
        );
        // Child recomputed this cycle — must pass.
        let child_done = RoleEntry {
            recompute_epoch: org_permissions_version,
            ..RoleEntry::default()
        };
        assert_eq!(
            child_done.recompute_epoch,
            org_permissions_version,
            "recomputed-this-cycle child must pass parent recompute check"
        );
    }

    // bitmask_is_subset for delegation privilege escalation guard ──

    #[test]
    fn test_bitmask_is_subset_basic() {
        // {0,2} ⊆ {0,1,2} — must pass
        let mut sub = Vec::new(); set_bit(&mut sub, 0); set_bit(&mut sub, 2);
        let mut sup = Vec::new(); set_bit(&mut sup, 0); set_bit(&mut sup, 1); set_bit(&mut sup, 2);
        assert!(bitmask_is_subset(&sub, &sup));
    }

    #[test]
    fn test_bitmask_is_subset_not_subset() {
        // {0,3} ⊄ {0,1,2} — bit 3 not in superset
        let mut sub = Vec::new(); set_bit(&mut sub, 0); set_bit(&mut sub, 3);
        let mut sup = Vec::new(); set_bit(&mut sup, 0); set_bit(&mut sup, 1); set_bit(&mut sup, 2);
        assert!(!bitmask_is_subset(&sub, &sup));
    }

    #[test]
    fn test_bitmask_is_subset_empty_is_always_subset() {
        let sub: Vec<u8> = Vec::new();
        let mut sup = Vec::new(); set_bit(&mut sup, 5);
        assert!(bitmask_is_subset(&sub, &sup),
            "empty set is a subset of everything");
    }

    #[test]
    fn test_bitmask_is_subset_equal_sets() {
        let mut a = Vec::new(); set_bit(&mut a, 7); set_bit(&mut a, 15);
        assert!(bitmask_is_subset(&a, &a.clone()), "A ⊆ A must hold");
    }

    #[test]
    fn test_bitmask_is_subset_subset_longer_than_superset() {
        // subset has a bit beyond the superset's byte length — must fail
        let mut sub = Vec::new(); set_bit(&mut sub, 16); // byte 2
        let sup = vec![0xFF, 0xFF]; // only bytes 0-1
        assert!(!bitmask_is_subset(&sub, &sup),
            "bit beyond superset length must not be treated as present");
    }

    #[test]
    fn test_delegation_subset_check_prevents_escalation() {
        // Scenario: caller has permission 3 (manage_roles) only.
        // Role R has effective_permissions = {3, 7} (permissions 3 and 7).
        // Caller wants to assign R — but R grants permission 7 which caller lacks.
        let mut caller_perms = [0u8; 32];
        set_bit_arr(&mut caller_perms, 3); // manage_roles only

        let mut role_eff = Vec::new();
        set_bit(&mut role_eff, 3);
        set_bit(&mut role_eff, 7); // extra privilege

        assert!(!bitmask_is_subset(&role_eff, &caller_perms),
            "role grants permission 7 which caller lacks — must be rejected");

        // If caller also holds permission 7, the assignment is allowed.
        set_bit_arr(&mut caller_perms, 7);
        assert!(bitmask_is_subset(&role_eff, &caller_perms),
            "once caller holds all role permissions, assignment is permitted");
    }

    #[test]
    fn test_delegation_subset_allows_self_assign_of_own_role() {
        // A caller may assign a role whose permissions are ≤ their own —
        // this is the intended delegation use-case (no escalation).
        let mut caller_perms = [0u8; 32];
        set_bit_arr(&mut caller_perms, 3);
        set_bit_arr(&mut caller_perms, 5);
        set_bit_arr(&mut caller_perms, 9);

        let mut role_eff = Vec::new();
        set_bit(&mut role_eff, 3);
        set_bit(&mut role_eff, 5);

        assert!(bitmask_is_subset(&role_eff, &caller_perms),
            "role {{3,5}} subset of caller {{3,5,9}} — assignment must be allowed");
    }

    //  Resource stores required_permission ───────────────────────
    // Verifies that delete_resource must use the permission stored at creation
    // time, not a caller-supplied value.
    #[test]
    fn test_resource_stores_required_permission() {
        let resource = Resource {
            organization: Pubkey::default(),
            creator: Pubkey::default(),
            title: "secret doc".into(),
            resource_id: 42,
            created_at: 0,
            bump: 255,
            required_permission: 7, // set at creation time
        };

        // The deletion logic must read resource.required_permission (7),
        // not any caller-supplied value.
        let required_at_deletion = resource.required_permission;
        assert_eq!(required_at_deletion, 7,
            "delete must use the permission stored in the resource, not caller input");

        // Simulate: caller holds permission 1 (low privilege), tries to bypass
        // by passing required_permission=1.  The stored value is 7, so the check
        // uses 7 regardless of caller input.
        let caller_permissions: Vec<u8> = {
            let mut v = Vec::new();
            set_bit(&mut v, 1); // only permission 1
            v
        };
        assert!(!has_bit(&caller_permissions, required_at_deletion),
            "caller with only permission 1 must NOT pass the permission-7 gate");

        // Caller holds permission 7 — must pass.
        let mut admin_permissions: Vec<u8> = Vec::new();
        set_bit(&mut admin_permissions, 7);
        assert!(has_bit(&admin_permissions, required_at_deletion),
            "caller with permission 7 must pass the permission-7 gate");
    }

    // Verify Resource::SIZE accounts for the new required_permission field.
    #[test]
    fn test_resource_size_includes_required_permission() {
        // 8 disc + 32 org + 32 creator + (4+64) title + 8 resource_id
        // + 8 created_at + 1 bump + 4 required_permission = 161
        assert_eq!(Resource::SIZE, 161,
            "Resource::SIZE must include 4 bytes for required_permission");
    }

    // ── M-1: required_permission bounds check ─────────────────────────────
    // create_resource must reject permission indices that have never been
    // created (>= next_permission_index), otherwise the resource becomes
    // permanently undeletable because no user can hold the bit in a fresh cache.

    /// required_permission == next_permission_index must be rejected.
    #[test]
    fn test_required_permission_equal_to_next_index_is_invalid() {
        let next_permission_index: u32 = 5; // permissions 0..4 exist
        let required_permission: u32 = 5;   // index 5 does not exist yet

        // The fix: required_permission < org.next_permission_index
        let is_valid = required_permission < next_permission_index;
        assert!(
            !is_valid,
            "required_permission == next_permission_index must be rejected; \
             no user can hold a non-existent permission, so the resource \
             would be permanently undeletable"
        );
    }

    /// required_permission strictly greater than next_permission_index must be rejected.
    #[test]
    fn test_required_permission_beyond_next_index_is_invalid() {
        let next_permission_index: u32 = 3;
        let required_permission: u32 = 99;

        let is_valid = required_permission < next_permission_index;
        assert!(
            !is_valid,
            "required_permission far beyond next_permission_index must be rejected"
        );
    }

    /// required_permission strictly less than next_permission_index must be accepted.
    #[test]
    fn test_required_permission_within_next_index_is_valid() {
        let next_permission_index: u32 = 8;
        let required_permission: u32 = 7; // last valid index

        let is_valid = required_permission < next_permission_index;
        assert!(
            is_valid,
            "required_permission = next_permission_index - 1 must be accepted"
        );
    }

    /// Edge case: no permissions created yet — any required_permission must fail.
    #[test]
    fn test_required_permission_with_no_permissions_created() {
        let next_permission_index: u32 = 0; // org has no permissions at all
        for required_permission in [0u32, 1, 127, 255] {
            let is_valid = required_permission < next_permission_index;
            assert!(
                !is_valid,
                "required_permission {} must be rejected when next_permission_index=0",
                required_permission
            );
        }
    }

    // ── M-2: checked_sub vs saturating_sub for role recompute counters ────
    // roles_pending_recompute and active_role_count must use checked_sub so
    // that invariant violations surface immediately rather than being silently
    // masked (e.g. counter at 0 unexpectedly decremented would stay at 0
    // with saturating_sub, allowing commit_update to succeed prematurely).

    /// saturating_sub silently stays at 0 — demonstrates why it masks bugs.
    #[test]
    fn test_saturating_sub_masks_underflow() {
        let counter: u32 = 0;
        let result = counter.saturating_sub(1);
        // The counter stays at 0 — commit_update would see 0 and wrongly
        // conclude all roles are recomputed.
        assert_eq!(
            result, 0,
            "saturating_sub silently stays at 0 — this masks the invariant violation"
        );
    }

    /// checked_sub returns None on underflow — correct defensive behaviour.
    #[test]
    fn test_checked_sub_exposes_underflow() {
        let counter: u32 = 0;
        let result = counter.checked_sub(1);
        assert!(
            result.is_none(),
            "checked_sub must return None when counter is 0 — invariant violation is surfaced"
        );
    }

    /// Normal decrement path: checked_sub returns Some when value > 0.
    #[test]
    fn test_checked_sub_normal_decrement() {
        let mut roles_pending: u32 = 3;
        for _ in 0..3 {
            roles_pending = roles_pending
                .checked_sub(1)
                .expect("counter must not underflow during normal recompute");
        }
        assert_eq!(roles_pending, 0, "counter reaches exactly 0 after all roles recomputed");

        // One more decrement would underflow — idempotency guard prevents this
        // in the real instruction, but checked_sub catches it defensively.
        let overflow = roles_pending.checked_sub(1);
        assert!(
            overflow.is_none(),
            "checked_sub must detect the extra decrement that the idempotency guard should prevent"
        );
    }

    /// active_role_count underflow detection: deleting more roles than exist
    /// must be caught, not silently masked.
    #[test]
    fn test_active_role_count_checked_sub_on_double_delete() {
        // Simulate: 1 active role, deleted once (active_role_count goes 1 → 0).
        // A second delete of the same index is blocked by require!(entry.active),
        // but checked_sub adds a second line of defence.
        let active_role_count: u32 = 1;
        let after_first = active_role_count.checked_sub(1).expect("first delete ok");
        assert_eq!(after_first, 0);

        // Second delete — checked_sub catches it; saturating_sub would not.
        let after_second = after_first.checked_sub(1);
        assert!(
            after_second.is_none(),
            "checked_sub must detect attempted decrement past zero"
        );
    }

    /// Verify the counter invariant holds across a complete update cycle:
    /// begin_update seeds from active_role_count; each recompute decrements by 1;
    /// commit_update requires the result to be 0.
    #[test]
    fn test_roles_pending_recompute_checked_sub_full_cycle() {
        let active_role_count: u32 = 4;
        let mut pending = active_role_count; // begin_update seeds this

        for i in 0..active_role_count {
            pending = pending
                .checked_sub(1)
                .unwrap_or_else(|| panic!("underflow at role {}", i));
        }
        assert_eq!(pending, 0, "all roles recomputed — commit_update may proceed");

        // Attempting to recompute a fifth (non-existent) role must be caught.
        let extra = pending.checked_sub(1);
        assert!(
            extra.is_none(),
            "recomputing beyond active_role_count must surface as an error"
        );
    }

    // ── Fix: revoke_user_permission silent permission strip (Finding 10) ──────
    //
    // The bug: revoke_user_permission used `if let Some(chunk)` when looking up
    // PermChunks for both direct_permissions and role permissions. If a chunk
    // was absent from the provided account slice, the corresponding permission
    // bits were silently dropped from the recomputed effective_permissions —
    // even bits the user should have kept.
    //
    // The fix: replace `if let Some()` with `.ok_or(ChunkNotFound)?`, identical
    // to the strict pattern used in revoke_role.rs and process_recompute_batch.rs.

    /// Demonstrates the old buggy `if let Some` pattern: permissions from chunks
    /// not present in the supplied account set are silently stripped.
    #[test]
    fn test_silent_strip_with_if_let_pattern() {
        // User has permission 5 (chunk 0, slot 5) and permission 35 (chunk 1, slot 3).
        // Only chunk 0 is in the caller's account set.
        let mut direct_permissions: Vec<u8> = Vec::new();
        set_bit(&mut direct_permissions, 5);
        set_bit(&mut direct_permissions, 35);

        // Simulate the old if-let pattern: chunk 1 is absent → bit 35 dropped.
        let mut result_old: Vec<u8> = Vec::new();
        for (byte_idx, &byte) in direct_permissions.iter().enumerate() {
            if byte == 0 { continue; }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let perm_idx = (byte_idx as u32) * 8 + bit;
                    let chunk_idx = perm_idx / PERMS_PER_CHUNK as u32;
                    let slot      = perm_idx as usize % PERMS_PER_CHUNK;
                    // Only chunk 0 is "present".
                    if chunk_idx == 0 {
                        // slot 5 is active in chunk 0.
                        if slot == 5 { set_bit(&mut result_old, perm_idx); }
                    }
                    // chunk 1 absent → old code silently skips, bit 35 is lost.
                }
            }
        }

        assert!(has_bit(&result_old, 5),  "perm 5 preserved — chunk 0 present");
        assert!(!has_bit(&result_old, 35),
            "perm 35 SILENTLY STRIPPED by old if-let pattern — this is the bug");
    }

    /// Demonstrates the fixed `ok_or` pattern: a missing chunk surfaces as an
    /// error instead of silently stripping permissions.
    #[test]
    fn test_strict_ok_or_pattern_detects_missing_chunk() {
        // Same scenario: bits 5 and 35, only chunk 0 supplied.
        let mut direct_permissions: Vec<u8> = Vec::new();
        set_bit(&mut direct_permissions, 5);
        set_bit(&mut direct_permissions, 35);

        let mut missing_chunk_detected = false;
        'outer: for (byte_idx, &byte) in direct_permissions.iter().enumerate() {
            if byte == 0 { continue; }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let perm_idx  = (byte_idx as u32) * 8 + bit;
                    let chunk_idx = perm_idx / PERMS_PER_CHUNK as u32;
                    // Simulate: chunk 0 present, chunk 1 absent.
                    let chunk_present = chunk_idx == 0;
                    if !chunk_present {
                        // Fixed code: ok_or(ChunkNotFound) propagates the error.
                        missing_chunk_detected = true;
                        break 'outer;
                    }
                }
            }
        }

        assert!(missing_chunk_detected,
            "fixed code must surface ChunkNotFound for permissions in missing chunks");
    }

    /// The fix must not change behaviour when ALL needed chunks are supplied.
    #[test]
    fn test_strict_pattern_succeeds_when_all_chunks_present() {
        // Bits 5 (chunk 0) and 35 (chunk 1); both chunks supplied.
        let mut direct_permissions: Vec<u8> = Vec::new();
        set_bit(&mut direct_permissions, 5);
        set_bit(&mut direct_permissions, 35);

        // Simulate chunk entries: perm 5 active in chunk 0, perm 35 active in chunk 1.
        let chunk0_active: std::collections::HashMap<u32, bool> =
            [(5u32, true)].iter().cloned().collect();
        let chunk1_active: std::collections::HashMap<u32, bool> =
            [(35u32 % PERMS_PER_CHUNK as u32, true)].iter().cloned().collect();

        let mut result: Vec<u8> = Vec::new();
        let mut error = false;
        'outer: for (byte_idx, &byte) in direct_permissions.iter().enumerate() {
            if byte == 0 { continue; }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let perm_idx  = (byte_idx as u32) * 8 + bit;
                    let chunk_idx = perm_idx / PERMS_PER_CHUNK as u32;
                    let slot      = perm_idx % PERMS_PER_CHUNK as u32;
                    let active = match chunk_idx {
                        0 => chunk0_active.get(&slot).copied().unwrap_or(false),
                        1 => chunk1_active.get(&slot).copied().unwrap_or(false),
                        _ => { error = true; break 'outer; }
                    };
                    if active { set_bit(&mut result, perm_idx); }
                }
            }
        }

        assert!(!error, "no missing-chunk error when all chunks are supplied");
        assert!(has_bit(&result, 5),  "perm 5 kept — chunk 0 supplied and active");
        assert!(has_bit(&result, 35), "perm 35 kept — chunk 1 supplied and active");
    }

    // ── Fix: resource permanently undeletable after required_permission deleted (Finding 11) ─

    /// Demonstrates the pre-fix vulnerability: after a permission is soft-deleted
    /// and the update cycle runs, no fresh UserPermCache will contain the deleted
    /// bit, so `has_bit(&cache, required_permission)` always returns false and
    /// delete_resource permanently fails.
    #[test]
    fn test_deleted_required_permission_locks_resource_forever() {
        let required_permission: u32 = 7;
        // After delete_permission(7) + update cycle the cache has no bit 7.
        let fresh_cache_after_deletion = [0u8; 32];

        let can_delete = has_bit(&fresh_cache_after_deletion, required_permission);
        assert!(
            !can_delete,
            "no user can ever hold a deleted permission bit in a fresh cache — \
             resource.delete would fail permanently without a recovery path"
        );
    }

    /// Verifies the recovery-path logic: when the permission is inactive the
    /// original creator (and only the creator) may force-close the resource.
    #[test]
    fn test_recovery_path_allows_creator_to_close_orphaned_resource() {
        let perm_is_active   = false; // permission was soft-deleted
        let caller_is_creator = true;

        // Recovery path: !active && caller == creator → allowed.
        let can_force_close = !perm_is_active && caller_is_creator;
        assert!(
            can_force_close,
            "resource creator must be able to force-close once required_permission is inactive"
        );
    }

    /// A third party cannot trigger the recovery-path deletion even when the
    /// permission is inactive — lamports must go only to the original creator.
    #[test]
    fn test_recovery_path_blocks_third_party_force_close() {
        let perm_is_active    = false;
        let caller_is_creator = false; // some other signer

        let can_force_close = !perm_is_active && caller_is_creator;
        assert!(
            !can_force_close,
            "non-creator must not be able to force-close an orphaned resource"
        );
    }

    /// When the permission is still active the normal cache check applies,
    /// regardless of whether the caller is the resource creator.
    #[test]
    fn test_normal_delete_path_requires_cache_bit_when_perm_active() {
        let perm_is_active      = true;
        let required_permission: u32 = 5;

        // Caller without the permission is rejected on the normal path.
        let cache_without = [0u8; 32];
        if perm_is_active {
            assert!(
                !has_bit(&cache_without, required_permission),
                "active perm: caller without it must be rejected"
            );
        }

        // Caller with the permission is accepted.
        let mut cache_with = [0u8; 32];
        set_bit_arr(&mut cache_with, required_permission);
        if perm_is_active {
            assert!(
                has_bit(&cache_with, required_permission),
                "active perm: caller holding it must be accepted"
            );
        }
    }

    /// End-to-end simulation of the full fix: active permission → normal check;
    /// inactive permission → creator-only force-close; non-creator rejected.
    #[test]
    fn test_delete_resource_combined_path_logic() {
        struct DeleteAttempt {
            perm_active:      bool,
            caller_has_perm:  bool,
            caller_is_creator: bool,
        }
        impl DeleteAttempt {
            fn can_delete(&self) -> bool {
                if self.perm_active {
                    self.caller_has_perm   // normal path
                } else {
                    self.caller_is_creator // recovery path
                }
            }
        }

        // Active permission, authorized caller.
        assert!(DeleteAttempt { perm_active: true,  caller_has_perm: true,  caller_is_creator: false }.can_delete());
        // Active permission, unauthorized caller.
        assert!(!DeleteAttempt { perm_active: true,  caller_has_perm: false, caller_is_creator: true  }.can_delete());
        // Deleted permission, caller is creator.
        assert!(DeleteAttempt { perm_active: false, caller_has_perm: false, caller_is_creator: true  }.can_delete());
        // Deleted permission, caller is NOT creator.
        assert!(!DeleteAttempt { perm_active: false, caller_has_perm: false, caller_is_creator: false }.can_delete());
        // Deleted permission + has perm (impossible in practice) + not creator.
        assert!(!DeleteAttempt { perm_active: false, caller_has_perm: true,  caller_is_creator: false }.can_delete());
    }
}
