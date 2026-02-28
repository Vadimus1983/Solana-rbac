use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Adds a child role to a parent role's `children` list.
///
/// Parent chunk is a named mutable account. If the child is in a different
/// chunk, pass that chunk as remaining_accounts[0] (readonly). If parent and
/// child share the same chunk, no additional account is needed.
#[derive(Accounts)]
#[instruction(parent_index: u32, child_index: u32)]
pub struct AddChildRole<'info> {
    /// The chunk containing the parent role (mutable).
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

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<AddChildRole>, parent_index: u32, child_index: u32) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );
    require!(parent_index > child_index, RbacError::CycleDetected);

    let parent_chunk_idx = parent_index / ROLES_PER_CHUNK as u32;
    let child_chunk_idx = child_index / ROLES_PER_CHUNK as u32;
    let parent_slot = parent_index as usize % ROLES_PER_CHUNK;
    let child_slot = child_index as usize % ROLES_PER_CHUNK;
    let org_key = ctx.accounts.organization.key();

    // Validate parent entry.
    {
        let chunk = &ctx.accounts.role_chunk;
        require!(parent_slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[parent_slot];
        require!(entry.topo_index == parent_index, RbacError::RoleSlotEmpty);
        require!(entry.active, RbacError::RoleInactive);
        require!(
            !entry.children.contains(&child_index),
            RbacError::RoleAlreadyAssigned
        );
    }

    // Validate child entry.
    if child_chunk_idx == parent_chunk_idx {
        // Same chunk — read directly.
        let chunk = &ctx.accounts.role_chunk;
        require!(child_slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let child_entry = &chunk.entries[child_slot];
        require!(child_entry.topo_index == child_index, RbacError::RoleSlotEmpty);
        require!(child_entry.active, RbacError::RoleInactive);
    } else {
        // Different chunk — must be supplied in remaining_accounts[0].
        let child_chunk = find_role_chunk_in_accounts(
            ctx.remaining_accounts,
            &org_key,
            child_chunk_idx,
            ctx.program_id,
        )?;
        require!(child_slot < child_chunk.entries.len(), RbacError::RoleSlotEmpty);
        let child_entry = &child_chunk.entries[child_slot];
        require!(child_entry.topo_index == child_index, RbacError::RoleSlotEmpty);
        require!(child_entry.active, RbacError::RoleInactive);
    }

    // Grow the chunk by 4 bytes for the new child_index (u32).
    let current_len = ctx.accounts.role_chunk.to_account_info().data_len();
    let new_space = current_len + 4;
    let rent = Rent::get()?;
    let new_min = rent.minimum_balance(new_space);
    let current_lamports = ctx.accounts.role_chunk.to_account_info().lamports();
    if current_lamports < new_min {
        let diff = new_min - current_lamports;
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: ctx.accounts.role_chunk.to_account_info(),
                },
            ),
            diff,
        )?;
    }
    ctx.accounts.role_chunk.to_account_info().resize(new_space)?;

    let chunk = &mut ctx.accounts.role_chunk;
    let parent_entry = &mut chunk.entries[parent_slot];
    parent_entry.children.push(child_index);
    parent_entry.version += 1;

    emit!(ChildRoleAdded {
        organization: org_key,
        parent_index,
        child_index,
    });

    msg!(
        "Child role index {} added to parent role index {}",
        child_index,
        parent_index
    );
    Ok(())
}
