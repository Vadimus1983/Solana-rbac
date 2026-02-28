use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(parent_index: u32)]
pub struct RemoveChildRole<'info> {
    #[account(
        mut,
        seeds = [
            b"role_chunk",
            organization.key().as_ref(),
            &(parent_index / ROLES_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = role_chunk.bump,
        constraint = role_chunk.organization == organization.key(),
    )]
    pub role_chunk: Account<'info, RoleChunk>,

    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<RemoveChildRole>, parent_index: u32, child_index: u32) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );

    let org_key = ctx.accounts.organization.key();
    let parent_slot = parent_index as usize % ROLES_PER_CHUNK;
    let chunk = &mut ctx.accounts.role_chunk;

    require!(parent_slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
    let entry = &mut chunk.entries[parent_slot];
    require!(entry.topo_index == parent_index, RbacError::RoleSlotEmpty);
    require!(entry.active, RbacError::RoleInactive);

    let pos = entry.children.iter().position(|&c| c == child_index);
    require!(pos.is_some(), RbacError::RoleNotAssigned);
    entry.children.swap_remove(pos.unwrap());
    entry.version += 1;

    emit!(ChildRoleRemoved {
        organization: org_key,
        parent_index,
        child_index,
    });

    msg!(
        "Child role index {} removed from parent role index {}",
        child_index,
        parent_index
    );
    Ok(())
}
