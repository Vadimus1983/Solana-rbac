use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(role_index: u32)]
pub struct DeleteRole<'info> {
    #[account(
        mut,
        seeds = [
            b"role_chunk",
            organization.key().as_ref(),
            &(role_index / ROLES_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = role_chunk.bump,
        constraint = role_chunk.organization == organization.key(),
    )]
    pub role_chunk: Account<'info, RoleChunk>,

    #[account(
        mut,
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<DeleteRole>, role_index: u32) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );

    let slot = role_index as usize % ROLES_PER_CHUNK;
    let chunk = &mut ctx.accounts.role_chunk;
    require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
    let entry = &mut chunk.entries[slot];
    require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
    require!(entry.active, RbacError::RoleInactive);

    let name = entry.name.clone();
    entry.active = false;
    entry.direct_permissions.clear();
    entry.effective_permissions.clear();
    entry.children.clear();
    entry.version += 1;

    // Issue #8: keep active_role_count in sync so begin_update can seed
    // roles_pending_recompute with the correct number of live roles.
    ctx.accounts.organization.active_role_count =
        ctx.accounts.organization.active_role_count.saturating_sub(1);

    emit!(RoleDeleted {
        organization: ctx.accounts.organization.key(),
        role_index,
        name,
    });

    msg!("Role index {} soft-deleted", role_index);
    Ok(())
}
