use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(perm_index: u32)]
pub struct DeletePermission<'info> {
    #[account(
        mut,
        seeds = [
            b"perm_chunk",
            organization.key().as_ref(),
            &(perm_index / PERMS_PER_CHUNK as u32).to_le_bytes(),
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

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<DeletePermission>, perm_index: u32) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );

    let slot = perm_index as usize % PERMS_PER_CHUNK;
    let chunk = &mut ctx.accounts.perm_chunk;
    require!(slot < chunk.entries.len(), RbacError::PermSlotEmpty);
    let entry = &mut chunk.entries[slot];
    require!(entry.index == perm_index, RbacError::PermSlotEmpty);
    require!(entry.active, RbacError::InvalidPermissionIndex);

    entry.active = false;

    emit!(PermissionDeleted {
        organization: ctx.accounts.organization.key(),
        perm_index,
    });

    msg!("Permission index {} soft-deleted", perm_index);
    Ok(())
}
