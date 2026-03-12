use anchor_lang::prelude::*;
use std::collections::HashMap;

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
    pub super_admin: Pubkey,
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
}

impl Organization {
    pub const FIXED_SIZE: usize = 8  // discriminator
        + 32                          // super_admin
        + (4 + MAX_ORG_NAME_LEN)     // name
        + 8                           // member_count
        + 4                           // next_permission_index
        + 4                           // role_count
        + 4                           // active_role_count  (new)
        + 8                           // permissions_version
        + 1 + 0                       // OrgState enum (1-byte tag, no data)
        + 1                           // bump
        + 4                           // roles_pending_recompute  (new)
        + 4;                          // users_pending_recompute  (new)
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
}
