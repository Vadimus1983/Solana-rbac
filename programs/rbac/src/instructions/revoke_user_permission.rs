use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Revoke a direct permission from a user. Works in **Idle** state.
///
/// Clears the bit in direct_permissions then fully recomputes effective_permissions
/// from the remaining direct_permissions plus all assigned roles.
/// Also updates UserPermCache.
///
/// remaining_accounts: deduplicated RoleChunk accounts for all roles assigned
/// to this user (readonly). If user has no roles, pass an empty slice.
#[derive(Accounts)]
pub struct RevokeUserPermission<'info> {
    #[account(
        mut,
        seeds = [
            b"user_account",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_account.bump,
        constraint = user_account.organization == organization.key(),
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(
        mut,
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            user_account.user.as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    #[account(
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<RevokeUserPermission>, permission_index: u32) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;

    let ua = &mut ctx.accounts.user_account;
    clear_bit(&mut ua.direct_permissions, permission_index);

    // Full recompute: direct_permissions (with bit cleared) ∪ all role effective_permissions.
    let mut result = ua.direct_permissions.clone();

    let roles_snapshot: Vec<RoleRef> = ua.assigned_roles.clone();
    let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(roles_snapshot.len());

    for role_ref in &roles_snapshot {
        let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
        let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
        let chunk = find_role_chunk_in_accounts(
            ctx.remaining_accounts,
            &org_key,
            chunk_idx,
            ctx.program_id,
        )?;
        let entry = &chunk.entries[slot];
        if entry.active {
            result = bitmask_union(&result, &entry.effective_permissions);
        }
        new_versions.push((role_ref.topo_index, entry.version));
    }

    // Update last_seen_version.
    for role_ref in ua.assigned_roles.iter_mut() {
        if let Some(&(_, v)) = new_versions.iter().find(|(ti, _)| *ti == role_ref.topo_index) {
            role_ref.last_seen_version = v;
        }
    }

    ua.effective_permissions = result;
    ua.cached_version = org_permissions_version;

    // Sync UserPermCache.
    let new_effective = ua.effective_permissions.clone();
    let cache = &mut ctx.accounts.user_perm_cache;
    copy_to_fixed(&mut cache.effective_permissions, &new_effective);
    cache.permissions_version = org_permissions_version;

    emit!(UserPermissionRevoked {
        organization: ctx.accounts.organization.key(),
        user: ctx.accounts.user_account.user,
        permission_index,
    });

    msg!(
        "Permission index {} revoked from user {}",
        permission_index,
        ctx.accounts.user_account.user
    );
    Ok(())
}
