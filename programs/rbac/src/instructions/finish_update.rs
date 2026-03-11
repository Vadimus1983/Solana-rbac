use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct FinishUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<FinishUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Recomputing, RbacError::OrgNotRecomputing);

    // All member UserAccounts must have been processed by
    // process_recompute_batch before the cycle can be closed.
    require!(
        org.users_pending_recompute == 0,
        RbacError::UpdateIncomplete
    );

    org.state = OrgState::Idle;

    msg!(
        "Organization '{}' finished recompute, now Idle (version {})",
        org.name,
        org.permissions_version
    );
    Ok(())
}
