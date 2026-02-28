use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Recomputes a role's `effective_permissions` from its `direct_permissions`
/// and the `effective_permissions` of all its direct children.
///
/// Children in the SAME chunk as this role are read directly from `role_chunk`.
/// Children in DIFFERENT chunks must be supplied in `remaining_accounts` as
/// readonly RoleChunk accounts (deduplicated: one account per unique chunk).
#[derive(Accounts)]
#[instruction(role_index: u32)]
pub struct RecomputeRole<'info> {
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

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<RecomputeRole>, role_index: u32) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );

    let parent_chunk_idx = role_index / ROLES_PER_CHUNK as u32;
    let slot = role_index as usize % ROLES_PER_CHUNK;
    let org_key = ctx.accounts.organization.key();

    {
        let chunk = &ctx.accounts.role_chunk;
        require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[slot];
        require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
        require!(entry.active, RbacError::RoleInactive);
    }

    // Clone data needed for computation to avoid borrow conflicts.
    let children: Vec<u32> = ctx.accounts.role_chunk.entries[slot].children.clone();
    let mut result: Vec<u8> = ctx.accounts.role_chunk.entries[slot].direct_permissions.clone();

    for &child_topo in &children {
        let child_chunk_idx = child_topo / ROLES_PER_CHUNK as u32;
        let child_slot = child_topo as usize % ROLES_PER_CHUNK;

        if child_chunk_idx == parent_chunk_idx {
            // Child is in the same chunk — read it directly.
            let chunk = &ctx.accounts.role_chunk;
            if child_slot < chunk.entries.len() {
                let child_entry = &chunk.entries[child_slot];
                if child_entry.active && child_entry.topo_index == child_topo {
                    result = bitmask_union(&result, &child_entry.effective_permissions);
                }
            }
        } else {
            // Child is in a different chunk — find it in remaining_accounts.
            let child_chunk = find_role_chunk_in_accounts(
                ctx.remaining_accounts,
                &org_key,
                child_chunk_idx,
                ctx.program_id,
            )?;
            if child_slot < child_chunk.entries.len() {
                let child_entry = &child_chunk.entries[child_slot];
                if child_entry.active && child_entry.topo_index == child_topo {
                    result = bitmask_union(&result, &child_entry.effective_permissions);
                }
            }
        }
    }

    // Grow the chunk if effective_permissions needs more bytes.
    let old_eff_len = ctx.accounts.role_chunk.entries[slot].effective_permissions.len();
    let new_eff_len = result.len();
    if new_eff_len > old_eff_len {
        let growth = new_eff_len - old_eff_len;
        let current_len = ctx.accounts.role_chunk.to_account_info().data_len();
        let new_space = current_len + growth;
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
    }

    let entry = &mut ctx.accounts.role_chunk.entries[slot];
    entry.effective_permissions = result;
    entry.version += 1;

    msg!("Role index {} effective_permissions recomputed", role_index);
    Ok(())
}
