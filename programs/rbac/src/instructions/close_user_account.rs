use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Closes a user's `UserAccount` and `UserPermCache`, reclaiming rent to the
/// authority. Decrements `member_count` so future `commit_update` cycles do
/// not include this user in `users_pending_recompute`.
///
/// The user must have no assigned roles and no direct permissions — the admin
/// must revoke everything first. This prevents orphaned role references.
#[derive(Accounts)]
pub struct CloseUserAccount<'info> {
    #[account(
        mut,
        close = authority,
        seeds = [
            b"user_account",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_account.bump,
        constraint = user_account.organization == organization.key(),
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(
        mut,
        close = authority,
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<CloseUserAccount>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let ua = &ctx.accounts.user_account;
    require!(ua.assigned_roles.is_empty(), RbacError::UserHasRoles);
    require!(
        ua.direct_permissions.iter().all(|&b| b == 0),
        RbacError::UserHasDirectPermissions
    );
    // Also assert effective_permissions is zeroed.
    // In a consistent state this follows from the two checks above (effective ⊇
    // direct, and effective ⊇ union-of-role-permissions).  However, if a bug
    // or out-of-order sequence left effective_permissions non-zero while
    // assigned_roles is empty and direct_permissions is zero (e.g., a partially
    // reverted inline recompute), we must refuse to close the account rather
    // than silently leaving residual permission bits that could affect a
    // recreated account at the same PDA.
    require!(
        ua.effective_permissions.iter().all(|&b| b == 0),
        RbacError::UserHasEffectivePermissions
    );

    org.member_count = org
        .member_count
        .checked_sub(1)
        .ok_or(error!(RbacError::MemberCountOverflow))?;

    msg!("User account closed for {}", ua.user);
    Ok(())
}
