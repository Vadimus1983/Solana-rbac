use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Creates a protected resource. The caller must have the specified permission.
#[derive(Accounts)]
#[instruction(title: String, resource_id: u64, required_permission: u32)]
pub struct CreateResource<'info> {
    #[account(
        init,
        payer = authority,
        space = Resource::SIZE,
        seeds = [
            b"resource",
            organization.key().as_ref(),
            authority.key().as_ref(),
            &resource_id.to_le_bytes(),
        ],
        bump,
    )]
    pub resource: Account<'info, Resource>,

    #[account(
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
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

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<CreateResource>,
    title: String,
    resource_id: u64,
    required_permission: u32,
) -> Result<()> {
    require!(
        title.len() <= MAX_RESOURCE_TITLE_LEN,
        RbacError::ResourceTitleTooLong
    );
    require!(required_permission < 256, RbacError::InvalidPermissionIndex);

    let cache = &ctx.accounts.user_perm_cache;
    let org = &ctx.accounts.organization;

    // Reject permission indices that have never been created — no user can
    // ever hold such a bit in a fresh cache, so the resource would be
    // permanently undeletable (lamports locked forever).
    require!(
        required_permission < org.next_permission_index,
        RbacError::InvalidPermissionIndex
    );

    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);
    require!(
        cache.permissions_version >= org.permissions_version,
        RbacError::StalePermissions
    );
    require!(
        has_bit(&cache.effective_permissions, required_permission),
        RbacError::InsufficientPermission
    );

    let resource = &mut ctx.accounts.resource;
    resource.organization = org.key();
    resource.creator = ctx.accounts.authority.key();
    resource.title = title;
    resource.resource_id = resource_id;
    resource.created_at = Clock::get()?.unix_timestamp;
    resource.bump = ctx.bumps.resource;
    resource.required_permission = required_permission;

    msg!(
        "Resource '{}' (id={}) created by {}",
        resource.title,
        resource.resource_id,
        resource.creator
    );
    Ok(())
}
