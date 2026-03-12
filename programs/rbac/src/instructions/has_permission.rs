use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Read-only verification: checks whether a user has a specific permission
/// using the fixed-size `UserPermCache` hot-path account.
///
/// Returns `StalePermissions` if the cache is out of date (admin must
/// recompute first). Returns `InsufficientPermission` if the user does
/// not have the permission.
#[derive(Accounts)]
pub struct HasPermission<'info> {
    #[account(
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
    )]
    pub organization: Account<'info, Organization>,

    /// CHECK: The wallet whose permission we are verifying.
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

pub fn handler(ctx: Context<HasPermission>, permission_index: u32) -> Result<()> {
    let org = &ctx.accounts.organization;
    let cache = &ctx.accounts.user_perm_cache;

    require!(
        cache.permissions_version >= org.permissions_version,
        RbacError::StalePermissions
    );
    require!(permission_index < 256, RbacError::InvalidPermissionIndex);
    require!(
        has_bit(&cache.effective_permissions, permission_index),
        RbacError::InsufficientPermission
    );

    emit!(AccessVerified {
        organization: org.key(),
        user: cache.user,
        has_access: true,
    });

    Ok(())
}
