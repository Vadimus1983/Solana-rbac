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

    #[account(mut)]
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

    // Reclaim the 4 bytes freed by swap_remove so lamports are not locked
    // indefinitely (add_child_role allocates +4 bytes; mirror that here).
    {
        let current_len = chunk.to_account_info().data_len();
        let new_space = current_len - 4;
        chunk.to_account_info().resize(new_space)?;
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(new_space);
        let current_lamports = chunk.to_account_info().lamports();
        if current_lamports > new_min {
            let excess = current_lamports - new_min;
            **chunk.to_account_info().try_borrow_mut_lamports()? -= excess;
            **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += excess;
        }
    }

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
