use anchor_lang::prelude::*;

#[error_code]
pub enum RbacError {
    #[msg("Organization name too long (max 32 characters)")]
    OrgNameTooLong,

    #[msg("Role name too long (max 32 characters)")]
    RoleNameTooLong,

    #[msg("Role description too long (max 128 characters)")]
    RoleDescTooLong,

    #[msg("Permission name too long (max 32 characters)")]
    PermissionNameTooLong,

    #[msg("Permission description too long (max 128 characters)")]
    PermissionDescTooLong,

    #[msg("Resource title too long (max 64 characters)")]
    ResourceTitleTooLong,

    #[msg("Unauthorized: caller is not the super admin")]
    NotSuperAdmin,

    #[msg("Unauthorized: caller lacks the required permission")]
    InsufficientPermission,

    #[msg("Invalid permission index")]
    InvalidPermissionIndex,

    #[msg("Invalid role index")]
    InvalidRoleIndex,

    #[msg("Missing authorization proof accounts")]
    MissingAuthProof,

    #[msg("Organization must be in Idle state for this operation")]
    OrgNotIdle,

    #[msg("Organization must be in Updating state for this operation")]
    OrgNotInUpdateMode,

    #[msg("Organization must be in Recomputing state for this operation")]
    OrgNotRecomputing,

    #[msg("Adding this child role would create a cycle (parent.topo_index must be > child.topo_index)")]
    CycleDetected,

    #[msg("Role is inactive (soft-deleted)")]
    RoleInactive,

    #[msg("Role is already assigned to this user")]
    RoleAlreadyAssigned,

    #[msg("Role is not assigned to this user")]
    RoleNotAssigned,

    #[msg("User permissions are stale — recompute required before on-chain verification")]
    StalePermissions,

    #[msg("Account count mismatch in remaining_accounts")]
    AccountCountMismatch,

    #[msg("Chunk is full (ROLES_PER_CHUNK or PERMS_PER_CHUNK limit reached)")]
    ChunkFull,

    #[msg("Role slot is empty or topo_index mismatch in this chunk")]
    RoleSlotEmpty,

    #[msg("Permission slot is empty or index mismatch in this chunk")]
    PermSlotEmpty,

    #[msg("Required chunk account not found in remaining_accounts")]
    ChunkNotFound,

    #[msg("Permission is inactive (soft-deleted) and cannot be assigned or added to a role")]
    PermissionInactive,

    #[msg("Update incomplete: not all roles/users have been recomputed yet")]
    UpdateIncomplete,

    /// Idempotency guard: recompute_role was already called for this role in the current update cycle.
    #[msg("Role was already recomputed in this update cycle")]
    AlreadyRecomputed,

    /// member_count exceeds the u32 range required for users_pending_recompute.
    #[msg("Member count exceeds u32 maximum; cannot track recompute progress")]
    MemberCountOverflow,

    /// role_count or active_role_count wrapped around u32::MAX.
    #[msg("Role count exceeds u32 maximum")]
    RoleCountOverflow,

    /// Permission is not directly assigned to this user or role.
    #[msg("Permission is not directly assigned to this user or role")]
    PermissionNotAssigned,

    /// Permission is already directly assigned to this role.
    #[msg("Permission is already directly assigned to this role")]
    PermissionAlreadyAssigned,

    /// permissions_version wrapped around u64::MAX.
    #[msg("Permissions version overflow")]
    VersionOverflow,

    /// When the organization has any permissions, PermChunk accounts must be
    /// supplied so that soft-deleted permission bits can be filtered out.
    #[msg("PermChunk accounts required when organization has permissions")]
    PermChunksRequired,
}
