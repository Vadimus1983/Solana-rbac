use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Revoke a role from a user. Works in **Idle** state.
///
/// After removing the role, the user's `effective_permissions` is fully
/// recomputed from their remaining roles (supplied in remaining_accounts as
/// deduplicated RoleChunk accounts) and their direct_permissions.
/// The `UserPermCache` is also updated in the same transaction.
///
/// remaining_accounts layout (AFTER the optional delegation account):
///   - If authority == super_admin: all remaining_accounts are role chunks.
///   - If delegated: remaining_accounts[0] is caller's UserPermCache,
///     remaining_accounts[1..] are role chunks.
#[derive(Accounts)]
pub struct RevokeRole<'info> {
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
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<RevokeRole>, role_index: u32) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;

    // Authorization check and determine offset into remaining_accounts for chunks.
    let chunks_offset: usize;
    if ctx.accounts.authority.key() != org.super_admin {
        require!(!ctx.remaining_accounts.is_empty(), RbacError::NotSuperAdmin);

        let cache_info = &ctx.remaining_accounts[0];
        require!(cache_info.owner == ctx.program_id, RbacError::NotSuperAdmin);

        let cache_data = cache_info
            .try_borrow_data()
            .map_err(|_| error!(RbacError::NotSuperAdmin))?;
        let caller_cache = UserPermCache::try_deserialize(&mut cache_data.as_ref())
            .map_err(|_| error!(RbacError::NotSuperAdmin))?;

        require!(
            caller_cache.user == ctx.accounts.authority.key(),
            RbacError::NotSuperAdmin
        );
        require!(
            caller_cache.organization == org_key,
            RbacError::NotSuperAdmin
        );
        require!(
            caller_cache.permissions_version >= org_permissions_version,
            RbacError::StalePermissions
        );
        require!(
            has_bit(&caller_cache.effective_permissions, MANAGE_ROLES_PERMISSION_INDEX),
            RbacError::InsufficientPermission
        );
        chunks_offset = 1;
    } else {
        chunks_offset = 0;
    }

    let role_chunks = &ctx.remaining_accounts[chunks_offset..];

    let ua = &mut ctx.accounts.user_account;

    // Remove the role reference.
    let pos = ua.assigned_roles.iter().position(|r| r.topo_index == role_index);
    require!(pos.is_some(), RbacError::RoleNotAssigned);
    ua.assigned_roles.swap_remove(pos.unwrap());

    // Full recompute: direct_permissions ∪ each remaining role's effective_permissions.
    let mut result = ua.direct_permissions.clone();

    // Collect new versions while computing.
    let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(ua.assigned_roles.len());
    for role_ref in ua.assigned_roles.iter() {
        let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
        let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
        let chunk = find_role_chunk_in_accounts(role_chunks, &org_key, chunk_idx, ctx.program_id)?;
        let entry = &chunk.entries[slot];
        if entry.active {
            result = bitmask_union(&result, &entry.effective_permissions);
        }
        new_versions.push((role_ref.topo_index, entry.version));
    }

    // Update last_seen_version for remaining roles.
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
    clear_bit_arr(&mut cache.effective_roles, role_index);
    cache.permissions_version = org_permissions_version;

    emit!(RoleRevoked {
        organization: org_key,
        user: ctx.accounts.user_account.user,
        role_index,
    });

    msg!("Role index {} revoked from user {}", role_index, ctx.accounts.user_account.user);
    Ok(())
}
