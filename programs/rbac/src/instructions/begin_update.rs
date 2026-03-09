use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct BeginUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<BeginUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    org.state = OrgState::Updating;
    // Issue #8: reset the role-recompute counter so commit_update can enforce
    // that every active role was recomputed before the cycle is closed.
    org.roles_pending_recompute = org.active_role_count;

    msg!("Organization '{}' entered Updating state ({} roles to recompute)", org.name, org.roles_pending_recompute);
    Ok(())
}
