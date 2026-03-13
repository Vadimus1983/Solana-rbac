use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Cancels an in-progress update cycle, returning the organization to Idle.
///
/// Without this instruction an org that enters Updating (or Recomputing) state
/// and never completes the cycle would be permanently locked — no Idle-only
/// operations (user management, role assignment, etc.) could ever run again.
///
/// Works from both `Updating` and `Recomputing` states.
#[derive(Accounts)]
pub struct CancelUpdate<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<CancelUpdate>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(
        org.state == OrgState::Updating || org.state == OrgState::Recomputing,
        RbacError::OrgNotInUpdateMode
    );

    org.state = OrgState::Idle;
    org.roles_pending_recompute = 0;
    org.users_pending_recompute = 0;

    msg!(
        "Organization '{}' update cancelled, reverted to Idle (version {})",
        org.name,
        org.permissions_version
    );
    Ok(())
}
