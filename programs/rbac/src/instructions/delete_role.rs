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
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
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
    // Capture whether this role has already been recomputed in the current
    // update cycle BEFORE modifying the entry. If it hasn't, releasing its
    // pending slot allows commit_update to complete after the deletion.
    let already_recomputed_this_cycle =
        entry.recompute_epoch == ctx.accounts.organization.permissions_version;
    entry.active = false;
    entry.direct_permissions.clear();
    entry.effective_permissions.clear();
    entry.children.clear();
    entry.version = entry
        .version
        .checked_add(1)
        .ok_or(error!(RbacError::VersionOverflow))?;

    // Keep active_role_count in sync so begin_update can seed
    // roles_pending_recompute with the correct number of live roles.
    // Use checked_sub: require!(entry.active) above guarantees this role was
    // counted, so underflow would indicate a state machine invariant violation.
    ctx.accounts.organization.active_role_count = ctx
        .accounts
        .organization
        .active_role_count
        .checked_sub(1)
        .ok_or(error!(RbacError::RoleCountOverflow))?;
    // Release the pending-recompute slot so the update cycle can still close
    // when a role is deleted before being recomputed this cycle.
    // Use checked_sub: the counter was seeded from active_role_count and
    // decremented at most once per active role, so underflow is a logic bug.
    if !already_recomputed_this_cycle {
        ctx.accounts.organization.roles_pending_recompute = ctx
            .accounts
            .organization
            .roles_pending_recompute
            .checked_sub(1)
            .ok_or(error!(RbacError::UpdateIncomplete))?;
    }

    emit!(RoleDeleted {
        organization: ctx.accounts.organization.key(),
        role_index,
        name,
    });

    msg!("Role index {} soft-deleted", role_index);
    Ok(())
}
