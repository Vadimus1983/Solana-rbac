use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct CreateUserAccount<'info> {
    #[account(
        init,
        payer = authority,
        space = UserAccount::BASE_SIZE,
        seeds = [
            b"user_account",
            organization.key().as_ref(),
            user.key().as_ref(),
        ],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(
        init,
        payer = authority,
        space = UserPermCache::SIZE,
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            user.key().as_ref(),
        ],
        bump,
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    /// CHECK: Wallet address of the user. No data read.
    pub user: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<CreateUserAccount>) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Idle,
        RbacError::OrgNotIdle
    );

    let org = &mut ctx.accounts.organization;
    // Guard against u32::MAX — commit_update casts member_count to u32 to seed
    // users_pending_recompute, so exceeding that range makes commit_update
    // permanently fail.
    require!(
        org.member_count < u32::MAX as u64,
        RbacError::MemberCountOverflow
    );
    org.member_count += 1;
    let org_permissions_version = org.permissions_version;
    let org_key = org.key();

    let ua = &mut ctx.accounts.user_account;
    ua.organization = org_key;
    ua.user = ctx.accounts.user.key();
    ua.assigned_roles = Vec::new();
    ua.direct_permissions = Vec::new();
    ua.effective_permissions = Vec::new();
    ua.cached_version = org_permissions_version;
    ua.bump = ctx.bumps.user_account;

    let cache = &mut ctx.accounts.user_perm_cache;
    cache.organization = org_key;
    cache.user = ctx.accounts.user.key();
    cache.effective_permissions = [0u8; 32];
    cache.effective_roles = [0u8; 32];
    cache.permissions_version = org_permissions_version;
    cache.bump = ctx.bumps.user_perm_cache;

    emit!(UserCreated {
        organization: org_key,
        user: ua.user,
    });

    msg!("User account created for {}", ua.user);
    Ok(())
}
