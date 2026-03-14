use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct BeginUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<BeginUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    // Advance the cycle nonce so this update cycle gets a unique epoch value.
    // Roles recomputed in a previous (possibly cancelled) cycle have an older
    // nonce and will be required to recompute again, preventing both
    // AlreadyRecomputed deadlocks and stale-permission bypasses.
    org.update_nonce = org
        .update_nonce
        .checked_add(1)
        .ok_or(error!(RbacError::UpdateCycleNonceOverflow))?;

    org.state = OrgState::Updating;
    // Reset the role-recompute counter so commit_update can enforce that every
    // active role was recomputed before the cycle is closed.
    org.roles_pending_recompute = org.active_role_count;

    msg!("Organization '{}' entered Updating state (nonce={}, {} roles to recompute)",
        org.name, org.update_nonce, org.roles_pending_recompute);
    Ok(())
}
