use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct CommitUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<CommitUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Updating, RbacError::OrgNotInUpdateMode);

    // Enforce that all active roles were recomputed before closing the Updating
    // phase — prevents stale effective_permissions from persisting into roles
    // after the cycle completes.
    require!(
        org.roles_pending_recompute == 0,
        RbacError::UpdateIncomplete
    );

    org.permissions_version = org
        .permissions_version
        .checked_add(1)
        .ok_or(error!(RbacError::VersionOverflow))?;
    org.state = OrgState::Recomputing;
    // Seed user recompute counter — finish_update enforces that every member's
    // UserAccount is processed before returning to Idle.
    org.users_pending_recompute = u32::try_from(org.member_count)
        .map_err(|_| error!(RbacError::MemberCountOverflow))?;

    msg!(
        "Organization '{}' committed update (version {}), entering Recomputing state ({} users to process)",
        org.name,
        org.permissions_version,
        org.users_pending_recompute,
    );
    Ok(())
}
