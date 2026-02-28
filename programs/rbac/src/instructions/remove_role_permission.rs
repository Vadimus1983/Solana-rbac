use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(role_index: u32)]
pub struct RemoveRolePermission<'info> {
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
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<RemoveRolePermission>, role_index: u32, permission_index: u32) -> Result<()> {
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

    clear_bit(&mut entry.direct_permissions, permission_index);
    entry.version += 1;

    emit!(RolePermissionRemoved {
        organization: ctx.accounts.organization.key(),
        role_index,
        permission_index,
    });

    msg!(
        "Permission index {} removed from role index {}",
        permission_index,
        role_index
    );
    Ok(())
}
