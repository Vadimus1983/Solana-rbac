use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Allows the super_admin to change which permission index grants delegation
/// (assign/revoke role) authority. Only works in Idle state so that in-flight
/// delegation checks are not affected mid-cycle.
#[derive(Accounts)]
pub struct UpdateManageRolesPermission<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<UpdateManageRolesPermission>, new_manage_roles_permission: u32) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);
    require!(new_manage_roles_permission < 256, RbacError::InvalidPermissionIndex);

    // The new index must refer to a permission that has actually been created,
    // preventing the admin from pointing delegation at a non-existent index
    // (which would make delegation permanently impossible).
    require!(
        new_manage_roles_permission < org.next_permission_index,
        RbacError::InvalidPermissionIndex
    );

    org.manage_roles_permission = new_manage_roles_permission;

    msg!(
        "manage_roles_permission updated to index {} for org '{}'",
        new_manage_roles_permission,
        org.name
    );
    Ok(())
}
