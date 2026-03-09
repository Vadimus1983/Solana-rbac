use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct CommitUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<CommitUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Updating, RbacError::OrgNotInUpdateMode);

    org.permissions_version += 1;
    org.state = OrgState::Recomputing;
    // Issue #8: seed user recompute counter — finish_update enforces that
    // every member's UserAccount is processed before returning to Idle.
    // Role completeness (roles_pending_recompute) is tracked for monitoring
    // but not enforced here, since only modified roles need recomputing.
    org.users_pending_recompute = org.member_count as u32;

    msg!(
        "Organization '{}' committed update (version {}), entering Recomputing state ({} users to process)",
        org.name,
        org.permissions_version,
        org.users_pending_recompute,
    );
    Ok(())
}
