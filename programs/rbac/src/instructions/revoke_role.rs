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

/// `perm_chunk_count` — number of PermChunk accounts at the START of the
/// caller-controlled portion of `remaining_accounts`, used to filter inactive
/// bits from `direct_permissions`.
///
/// remaining_accounts layout:
///   super_admin path: [perm_chunks (0..pcc), role_chunks (pcc..)]
///   delegated path:   [caller_cache (0), perm_chunks (1..1+pcc), role_chunks (1+pcc..)]
pub fn handler(ctx: Context<RevokeRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;

    // Authorization check; determine where perm_chunks start in remaining_accounts.
    let base_offset: usize;
    if ctx.accounts.authority.key() != org.super_admin {
        require!(!ctx.remaining_accounts.is_empty(), RbacError::NotSuperAdmin);

        let cache_info = &ctx.remaining_accounts[0];
        require!(cache_info.owner == ctx.program_id, RbacError::NotSuperAdmin);

        // Verify PDA derivation to prevent cross-org privilege escalation.
        let (expected_pda, _) = Pubkey::find_program_address(
            &[
                b"user_perm_cache",
                org_key.as_ref(),
                ctx.accounts.authority.key().as_ref(),
            ],
            ctx.program_id,
        );
        require!(cache_info.key() == expected_pda, RbacError::NotSuperAdmin);

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
        base_offset = 1;
    } else {
        base_offset = 0;
    }

    let pcc = perm_chunk_count as usize;
    let perm_accounts = &ctx.remaining_accounts[base_offset..base_offset + pcc];
    let role_chunks = &ctx.remaining_accounts[base_offset + pcc..];

    let ua = &mut ctx.accounts.user_account;

    // Remove the role reference.
    let pos = ua.assigned_roles.iter().position(|r| r.topo_index == role_index);
    require!(pos.is_some(), RbacError::RoleNotAssigned);
    ua.assigned_roles.swap_remove(pos.unwrap());

    // Full recompute: filter direct_permissions through PermChunks (stale bits
    // from soft-deleted permissions are dropped), then union each remaining
    // role's effective_permissions.
    let mut result: Vec<u8> = Vec::new();
    for (byte_idx, &byte) in ua.direct_permissions.iter().enumerate() {
        if byte == 0 { continue; }
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                let perm_index = (byte_idx as u32) * 8 + bit;
                if pcc > 0 {
                    let perm_chunk_idx = perm_index / PERMS_PER_CHUNK as u32;
                    let perm_slot = perm_index as usize % PERMS_PER_CHUNK;
                    if let Ok(perm_chunk) = find_perm_chunk_in_accounts(
                        perm_accounts,
                        &org_key,
                        perm_chunk_idx,
                        ctx.program_id,
                    ) {
                        if perm_slot < perm_chunk.entries.len()
                            && perm_chunk.entries[perm_slot].index == perm_index
                            && perm_chunk.entries[perm_slot].active
                        {
                            set_bit(&mut result, perm_index);
                        }
                        // inactive or not in entries → bit silently dropped
                    }
                    // chunk not in accounts → treat as inactive, drop bit
                } else {
                    // pcc == 0: no perm chunks supplied — include bit as-is.
                    set_bit(&mut result, perm_index);
                }
            }
        }
    }

    // Collect new versions while computing role union.
    // Filter each role's effective_permissions through PermChunks (same as
    // process_recompute_batch) so deleted permission bits don't leak back in
    // when roles haven't been recomputed since the last permission deletion.
    let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(ua.assigned_roles.len());
    for role_ref in ua.assigned_roles.iter() {
        let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
        let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
        let chunk = find_role_chunk_in_accounts(role_chunks, &org_key, chunk_idx, ctx.program_id)?;
        let entry = &chunk.entries[slot];
        if entry.active {
            for (byte_idx, &byte) in entry.effective_permissions.iter().enumerate() {
                if byte == 0 { continue; }
                for bit in 0..8u32 {
                    if byte & (1 << bit) != 0 {
                        let perm_index = (byte_idx as u32) * 8 + bit;
                        if pcc > 0 {
                            let perm_chunk_idx = perm_index / PERMS_PER_CHUNK as u32;
                            let perm_slot = perm_index as usize % PERMS_PER_CHUNK;
                            if let Ok(perm_chunk) = find_perm_chunk_in_accounts(
                                perm_accounts,
                                &org_key,
                                perm_chunk_idx,
                                ctx.program_id,
                            ) {
                                if perm_slot < perm_chunk.entries.len()
                                    && perm_chunk.entries[perm_slot].index == perm_index
                                    && perm_chunk.entries[perm_slot].active
                                {
                                    set_bit(&mut result, perm_index);
                                }
                                // inactive or not in entries → bit silently dropped
                            }
                            // chunk not in accounts → treat permission as inactive, drop bit
                        } else {
                            set_bit(&mut result, perm_index);
                        }
                    }
                }
            }
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

    // Resize the UserAccount to reclaim rent released by removing a RoleRef
    // (12 bytes) and the potentially shorter recomputed effective_permissions.
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
