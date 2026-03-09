use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
#[instruction(role_index: u32, permission_index: u32)]
pub struct AddRolePermission<'info> {
    #[account(
        mut,
        seeds = [
            b"role_chunk",
            organization.key().as_ref(),
            &(role_index / ROLES_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = role_chunk.bump,
        constraint = role_chunk.organization == organization.key(),
    )]
    pub role_chunk: Account<'info, RoleChunk>,

    /// The chunk containing the permission. Read-only; used to verify the
    /// permission is still active (Issue #6 fix).
    #[account(
        seeds = [
            b"perm_chunk",
            organization.key().as_ref(),
            &(permission_index / PERMS_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = perm_chunk.bump,
        constraint = perm_chunk.organization == organization.key(),
    )]
    pub perm_chunk: Account<'info, PermChunk>,

    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<AddRolePermission>,
    role_index: u32,
    permission_index: u32,
) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Updating, RbacError::OrgNotInUpdateMode);
    require!(permission_index < org.next_permission_index, RbacError::InvalidPermissionIndex);

    // Issue #6: reject soft-deleted permissions — recompute_role would drop them
    // anyway, but this gives an immediate, clear error at the call site.
    let perm_slot = permission_index as usize % PERMS_PER_CHUNK;
    let perm_chunk = &ctx.accounts.perm_chunk;
    require!(perm_slot < perm_chunk.entries.len(), RbacError::PermSlotEmpty);
    require!(
        perm_chunk.entries[perm_slot].index == permission_index,
        RbacError::PermSlotEmpty
    );
    require!(
        perm_chunk.entries[perm_slot].active,
        RbacError::PermissionInactive
    );

    let slot = role_index as usize % ROLES_PER_CHUNK;
    {
        let chunk = &ctx.accounts.role_chunk;
        require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[slot];
        require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
        require!(entry.active, RbacError::RoleInactive);
    }

    // Compute growth needed to hold this bit index.
    let needed = bitmask_bytes_for(permission_index);
    let current_direct_len = ctx.accounts.role_chunk.entries[slot].direct_permissions.len();
    let growth = if needed > current_direct_len {
        needed - current_direct_len
    } else {
        0
    };

    if growth > 0 {
        let current_len = ctx.accounts.role_chunk.to_account_info().data_len();
        let new_space = current_len + growth;
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(new_space);
        let current_lamports = ctx.accounts.role_chunk.to_account_info().lamports();
        if current_lamports < new_min {
            let diff = new_min - current_lamports;
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.authority.to_account_info(),
                        to: ctx.accounts.role_chunk.to_account_info(),
                    },
                ),
                diff,
            )?;
        }
        ctx.accounts.role_chunk.to_account_info().resize(new_space)?;
    }

    let chunk = &mut ctx.accounts.role_chunk;
    let entry = &mut chunk.entries[slot];
    set_bit(&mut entry.direct_permissions, permission_index);
    entry.version += 1;

    emit!(RolePermissionAdded {
        organization: ctx.accounts.organization.key(),
        role_index,
        permission_index,
    });

    msg!(
        "Permission index {} added to role index {}",
        permission_index,
        role_index
    );
    Ok(())
}
