use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Revoke a direct permission from a user. Works in **Idle** state.
///
/// Clears the bit in direct_permissions then fully recomputes effective_permissions
/// from the remaining direct_permissions plus all assigned roles.
/// Also updates UserPermCache.
///
/// `perm_chunk_count` — number of PermChunk accounts at the START of
/// `remaining_accounts`, used to filter inactive bits still present in
/// `direct_permissions` after the clear.
///
/// remaining_accounts layout:
///   [perm_chunks (0..pcc), role_chunks (pcc..)]
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
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<RevokeUserPermission>, permission_index: u32, perm_chunk_count: u8) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;
    let next_permission_index = org.next_permission_index;

    let pcc = perm_chunk_count as usize;
    require!(
        org.next_permission_index == 0 || pcc > 0,
        RbacError::PermChunksRequired
    );

    let ua = &mut ctx.accounts.user_account;
    require!(permission_index < next_permission_index, RbacError::InvalidPermissionIndex);
    require!(has_bit(&ua.direct_permissions, permission_index), RbacError::PermissionNotAssigned);
    clear_bit(&mut ua.direct_permissions, permission_index);
    let perm_accounts = &ctx.remaining_accounts[..pcc];
    let role_accounts = &ctx.remaining_accounts[pcc..];

    // Index chunks once for O(1) lookups.
    let perm_index = if pcc > 0 {
        Some(build_perm_chunk_index(perm_accounts, &org_key, ctx.program_id)?)
    } else {
        None
    };
    let role_chunk_index = build_role_chunk_index(role_accounts, &org_key, ctx.program_id)?;

    // Full recompute: filter direct_permissions (post-clear) through PermChunks
    // (stale bits from soft-deleted permissions are dropped), then union each
    // assigned role's effective_permissions.
    let mut result: Vec<u8> = Vec::new();
    for (byte_idx, &byte) in ua.direct_permissions.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                let perm_index_val = (byte_idx as u32) * 8 + bit;
                let perm_chunk_idx = perm_index_val / PERMS_PER_CHUNK as u32;
                let perm_slot = perm_index_val as usize % PERMS_PER_CHUNK;
                if pcc > 0 {
                    if let Some(perm_chunk) =
                        perm_index.as_ref().and_then(|idx| idx.get(&perm_chunk_idx))
                    {
                        if perm_slot < perm_chunk.entries.len()
                            && perm_chunk.entries[perm_slot].index == perm_index_val
                            && perm_chunk.entries[perm_slot].active
                        {
                            set_bit(&mut result, perm_index_val);
                        }
                        // inactive or not in entries → bit silently dropped
                    }
                    // chunk not in accounts → treat as inactive, drop bit
                } else {
                    // pcc == 0: no perm chunks supplied — include bit as-is.
                    set_bit(&mut result, perm_index_val);
                }
            }
        }
    }

    let roles_snapshot: Vec<RoleRef> = ua.assigned_roles.clone();
    let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(roles_snapshot.len());

    // Filter each role's effective_permissions through PermChunks so deleted
    // permission bits don't leak back in when roles haven't been recomputed
    // since the last permission deletion (mirrors process_recompute_batch).
    for role_ref in &roles_snapshot {
        let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
        let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
        let chunk = role_chunk_index
            .get(&chunk_idx)
            .ok_or(RbacError::ChunkNotFound)?;
        require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[slot];
        require!(entry.topo_index == role_ref.topo_index, RbacError::RoleSlotEmpty);
        if entry.active {
            for (byte_idx, &byte) in entry.effective_permissions.iter().enumerate() {
                if byte == 0 {
                    continue;
                }
                for bit in 0..8u32 {
                    if byte & (1 << bit) != 0 {
                        let perm_index_val = (byte_idx as u32) * 8 + bit;
                        if pcc > 0 {
                            let perm_chunk_idx = perm_index_val / PERMS_PER_CHUNK as u32;
                            let perm_slot = perm_index_val as usize % PERMS_PER_CHUNK;
                            if let Some(perm_chunk) =
                                perm_index.as_ref().and_then(|idx| idx.get(&perm_chunk_idx))
                            {
                                if perm_slot < perm_chunk.entries.len()
                                    && perm_chunk.entries[perm_slot].index == perm_index_val
                                    && perm_chunk.entries[perm_slot].active
                                {
                                    set_bit(&mut result, perm_index_val);
                                }
                                // inactive or not in entries → bit silently dropped
                            }
                            // chunk not in accounts → treat permission as inactive, drop bit
                        } else {
                            set_bit(&mut result, perm_index_val);
                        }
                    }
                }
            }
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

    // Resize the UserAccount to reclaim rent released by the shorter
    // recomputed effective_permissions after clearing a direct permission.
    {
        let new_space = ua.current_size();
        let ua_info = ua.to_account_info();
        ua_info.resize(new_space)?;
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(new_space);
        let current_lamports = ua_info.lamports();
        if current_lamports > new_min {
            let excess = current_lamports - new_min;
            **ua_info.try_borrow_mut_lamports()? -= excess;
            **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += excess;
        }
    }

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
