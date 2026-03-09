use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Read-only verification: checks whether a user has a specific role
/// using the O(1) bitmask on `UserPermCache`.
#[derive(Accounts)]
pub struct HasRole<'info> {
    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
    )]
    pub organization: Account<'info, Organization>,

    /// CHECK: The wallet whose role we are verifying.
    pub user: UncheckedAccount<'info>,

    #[account(
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            user.key().as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
        constraint = user_perm_cache.user == user.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,
}

pub fn handler(ctx: Context<HasRole>, role_index: u32) -> Result<()> {
    let cache = &ctx.accounts.user_perm_cache;

    require!(role_index < 256, RbacError::InvalidRoleIndex);

    // Issue #4: reject stale caches — a deleted role would still appear in
    // effective_roles until process_recompute_batch updates the cache.
    require!(
        cache.permissions_version >= ctx.accounts.organization.permissions_version,
        RbacError::StalePermissions
    );

    require!(
        has_bit(&cache.effective_roles, role_index),
        RbacError::RoleNotAssigned
    );

    emit!(AccessVerified {
        organization: ctx.accounts.organization.key(),
        user: cache.user,
        has_access: true,
    });

    Ok(())
}
