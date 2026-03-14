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

    // Advance the update nonce so roles recomputed in this cancelled cycle
    // are NOT treated as "already recomputed" in the next begin_update cycle.
    // Without this increment two bugs occur:
    //   (a) Deadlock: those roles fire AlreadyRecomputed on the next cycle
    //       (same nonce), so commit_update can never reach roles_pending == 0.
    //   (b) Stale perms: revoke_role's subset check could use effective_perms
    //       that don't reflect direct_perm changes made in the cancelled cycle.
    org.update_nonce = org
        .update_nonce
        .checked_add(1)
        .ok_or(error!(RbacError::UpdateCycleNonceOverflow))?;

    msg!(
        "Organization '{}' update cancelled, reverted to Idle (version {}, nonce {})",
        org.name,
        org.permissions_version,
        org.update_nonce,
    );
    Ok(())
}
