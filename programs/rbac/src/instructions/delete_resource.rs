use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Deletes a resource. The caller must have the specified permission.
#[derive(Accounts)]
#[instruction(required_permission: u32)]
pub struct DeleteResource<'info> {
    #[account(
        mut,
        close = authority,
        seeds = [
            b"resource",
            organization.key().as_ref(),
            &resource.resource_id.to_le_bytes(),
        ],
        bump = resource.bump,
        constraint = resource.organization == organization.key(),
    )]
    pub resource: Account<'info, Resource>,

    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
    )]
    pub organization: Account<'info, Organization>,

    #[account(
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            authority.key().as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
        constraint = user_perm_cache.user == authority.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<DeleteResource>, required_permission: u32) -> Result<()> {
    let cache = &ctx.accounts.user_perm_cache;
    let org = &ctx.accounts.organization;

    require!(
        cache.permissions_version >= org.permissions_version,
        RbacError::StalePermissions
    );
    require!(
        has_bit(&cache.effective_permissions, required_permission),
        RbacError::InsufficientPermission
    );

    msg!(
        "Resource '{}' (id={}) deleted by {}",
        ctx.accounts.resource.title,
        ctx.accounts.resource.resource_id,
        ctx.accounts.authority.key()
    );
    Ok(())
}
