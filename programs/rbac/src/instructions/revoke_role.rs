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
#[instruction(role_index: u32)]
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

    /// The chunk containing the role being revoked (readonly).  Required on
    /// the delegated path so we can verify the caller holds all permissions
    /// of that role (subset check), preventing privilege escalation via revoke.
    #[account(
        seeds = [
            b"role_chunk",
            organization.key().as_ref(),
            &(role_index / ROLES_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump = role_chunk.bump,
        constraint = role_chunk.organization == organization.key(),
    )]
    pub role_chunk: Account<'info, RoleChunk>,

    #[account(
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
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

    let pcc = perm_chunk_count as usize;
    // Require PermChunks when org has permissions so deleted permission bits are filtered out.
    require!(
        org.next_permission_index == 0 || pcc > 0,
        RbacError::PermChunksRequired
    );

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;

    // Authorization check; determine where perm_chunks start in remaining_accounts.
    // On the delegated path we also capture the caller's effective_permissions
    // so we can enforce the subset check below.
    let base_offset: usize;
    let caller_effective_perms: Option<[u8; 32]>;
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
            caller_cache.permissions_version == org_permissions_version,
            RbacError::StalePermissions
        );
        require!(
            has_bit(&caller_cache.effective_permissions, org.manage_roles_permission),
            RbacError::InsufficientPermission
        );
        caller_effective_perms = Some(caller_cache.effective_permissions);
        base_offset = 1;
    } else {
        caller_effective_perms = None;
        base_offset = 0;
    }

    // Delegated-path privilege-escalation guard: a delegated manager may only
    // revoke a role whose effective permissions are a subset of their own.
    // We read from the named role_chunk (in Idle state its effective_permissions
    // are already filtered by the last recompute_role call, so raw == filtered).
    if let Some(ref caller_perms) = caller_effective_perms {
        let slot = role_index as usize % ROLES_PER_CHUNK;
        let chunk = &ctx.accounts.role_chunk;
        require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[slot];
        require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
        require!(
            bitmask_is_subset(&entry.effective_permissions, caller_perms),
            RbacError::InsufficientPermission
        );
    }

    require!(
        base_offset + pcc <= ctx.remaining_accounts.len(),
        RbacError::AccountCountMismatch
    );
    let perm_accounts = &ctx.remaining_accounts[base_offset..base_offset + pcc];
    let role_chunks = &ctx.remaining_accounts[base_offset + pcc..];

    // Index chunks once for O(1) lookups.
    let perm_index = if pcc > 0 {
        Some(build_perm_chunk_index(perm_accounts, &org_key, ctx.program_id)?)
    } else {
        None
    };
    let role_chunk_index = build_role_chunk_index(role_chunks, &org_key, ctx.program_id)?;

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
        if byte == 0 {
            continue;
        }
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                let perm_index_val = (byte_idx as u32) * 8 + bit;
                if pcc > 0 {
                    let perm_chunk_idx = perm_index_val / PERMS_PER_CHUNK as u32;
                    let perm_slot = perm_index_val as usize % PERMS_PER_CHUNK;
                    let perm_chunk = perm_index
                        .as_ref()
                        .and_then(|idx| idx.get(&perm_chunk_idx))
                        .ok_or(RbacError::ChunkNotFound)?;
                    if perm_slot < perm_chunk.entries.len()
                        && perm_chunk.entries[perm_slot].index == perm_index_val
                        && perm_chunk.entries[perm_slot].active
                    {
                        set_bit(&mut result, perm_index_val);
                    }
                } else {
                    // pcc == 0: no perm chunks supplied — include bit as-is.
                    set_bit(&mut result, perm_index_val);
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
                            let perm_chunk = perm_index
                                .as_ref()
                                .and_then(|idx| idx.get(&perm_chunk_idx))
                                .ok_or(RbacError::ChunkNotFound)?;
                            if perm_slot < perm_chunk.entries.len()
                                && perm_chunk.entries[perm_slot].index == perm_index_val
                                && perm_chunk.entries[perm_slot].active
                            {
                                set_bit(&mut result, perm_index_val);
                            }
                        } else {
                            set_bit(&mut result, perm_index_val);
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
