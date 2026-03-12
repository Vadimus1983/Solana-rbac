use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Transfer super-admin authority to a new account. Works in **Idle** state only.
///
/// The org PDA address never changes because its seeds use `original_admin`
/// (set once at initialization), not the mutable `super_admin` field.
#[derive(Accounts)]
pub struct TransferSuperAdmin<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    /// The account that will become the new super_admin.
    pub new_super_admin: SystemAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<TransferSuperAdmin>) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);
    require!(
        ctx.accounts.new_super_admin.key() != org.super_admin,
        RbacError::AlreadySuperAdmin
    );

    let old = org.super_admin;
    org.super_admin = ctx.accounts.new_super_admin.key();

    msg!(
        "Super admin transferred from {} to {}",
        old,
        org.super_admin
    );
    Ok(())
}
