use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Grant a direct permission to a user. Works in **Idle** state.
/// Sets the bit in both direct_permissions and effective_permissions inline.
/// Also updates UserPermCache.
///
/// Issue #3 fix: the PermChunk for the target permission is now a required
/// account; the handler verifies the permission is still active before granting.
#[derive(Accounts)]
#[instruction(permission_index: u32)]
pub struct AssignUserPermission<'info> {
    #[account(
        mut,
        seeds = [
            b"user_account",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_account.bump,
        constraint = user_account.organization == organization.key(),
        realloc = UserAccount::BASE_SIZE + {
            let needed = bitmask_bytes_for(permission_index);
            let new_direct = user_account.direct_permissions.len().max(needed);
            let new_effective = user_account.effective_permissions.len().max(needed);
            user_account.assigned_roles.len() * 12
                + new_direct
                + new_effective
        },
        realloc::payer = authority,
        realloc::zero = false,
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(
        mut,
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    /// The chunk containing the permission. Read-only; used to verify the
    /// permission is still active (Issue #3 fix).
    #[account(
        seeds = [
            b"perm_chunk",
            organization.key().as_ref(),
            &(permission_index / PERMS_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = perm_chunk.bump,
        constraint = perm_chunk.organization == organization.key(),
    )]
    pub perm_chunk: Account<'info, PermChunk>,

    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<AssignUserPermission>, permission_index: u32) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);
    require!(permission_index < org.next_permission_index, RbacError::InvalidPermissionIndex);

    // Issue #3: reject soft-deleted permissions to prevent resurrecting revoked access.
    let perm_slot = permission_index as usize % PERMS_PER_CHUNK;
    let perm_chunk = &ctx.accounts.perm_chunk;
    require!(perm_slot < perm_chunk.entries.len(), RbacError::PermSlotEmpty);
    require!(
        perm_chunk.entries[perm_slot].index == permission_index,
        RbacError::PermSlotEmpty
    );
    require!(
        perm_chunk.entries[perm_slot].active,
        RbacError::PermissionInactive
    );

    let org_permissions_version = org.permissions_version;
    let ua = &mut ctx.accounts.user_account;

    set_bit(&mut ua.direct_permissions, permission_index);
    // Adding to direct also adds to effective (effective ⊇ direct always).
    set_bit(&mut ua.effective_permissions, permission_index);
    ua.cached_version = org_permissions_version;

    // Sync UserPermCache.
    let cache = &mut ctx.accounts.user_perm_cache;
    set_bit_arr(&mut cache.effective_permissions, permission_index);
    cache.permissions_version = org_permissions_version;

    emit!(UserPermissionGranted {
        organization: ctx.accounts.organization.key(),
        user: ctx.accounts.user_account.user,
        permission_index,
    });

    msg!(
        "Permission index {} assigned directly to user {}",
        permission_index,
        ctx.accounts.user_account.user
    );
    Ok(())
}
