use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(name: String)]
pub struct InitializeOrganization<'info> {
    #[account(
        init,
        payer = authority,
        space = Organization::FIXED_SIZE,
        seeds = [b"organization", name.as_bytes()],
        bump,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeOrganization>, name: String) -> Result<()> {
    require!(name.len() <= MAX_ORG_NAME_LEN, RbacError::OrgNameTooLong);

    let org = &mut ctx.accounts.organization;
    org.super_admin = ctx.accounts.authority.key();
    org.name = name;
    org.member_count = 0;
    org.next_permission_index = 0;
    org.role_count = 0;
    org.active_role_count = 0;
    org.permissions_version = 0;
    org.state = OrgState::Idle;
    org.bump = ctx.bumps.organization;
    org.roles_pending_recompute = 0;
    org.users_pending_recompute = 0;

    emit!(OrgCreated {
        organization: org.key(),
        name: org.name.clone(),
        super_admin: org.super_admin,
    });

    msg!("Organization '{}' created by {}", org.name, org.super_admin);
    Ok(())
}
