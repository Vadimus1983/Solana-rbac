use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Recomputes `effective_permissions` for a batch of UserAccounts after structural
/// changes (schema: Updating → commit → Recomputing). Role assignments/revocations
/// in Idle state no longer require this batch.
///
/// remaining_accounts layout (repeated for each user in batch):
///   - UserAccount (writable)
///   - UserPermCache (writable)
///   - RoleChunk_a (readonly), RoleChunk_b (readonly), ...  ← deduplicated per user
///
/// `user_chunk_counts[i]` = number of RoleChunk accounts following UserAccount+UserPermCache pair i.
/// A user with no roles has user_chunk_counts[i] = 0.
#[derive(Accounts)]
pub struct ProcessRecomputeBatch<'info> {
    #[account(
        mut,
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// remaining_accounts layout:
///   [0 .. perm_chunk_count)  — readonly PermChunk accounts (for filtering direct_permissions)
///   [perm_chunk_count ..)    — per-user groups: UA (writable), UPC (writable), RoleChunks...
pub fn handler(
    ctx: Context<ProcessRecomputeBatch>,
    user_chunk_counts: Vec<u8>,
    perm_chunk_count: u8,
) -> Result<()> {
    {
        let org = &ctx.accounts.organization;
        require!(org.state == OrgState::Recomputing, RbacError::OrgNotRecomputing);
    }

    let org = &ctx.accounts.organization;
    // Require PermChunks when org has permissions so deleted permission bits are filtered out.
    let pcc = perm_chunk_count as usize;
    require!(
        org.next_permission_index == 0 || pcc > 0,
        RbacError::PermChunksRequired
    );
    require!(
        pcc <= ctx.remaining_accounts.len(),
        RbacError::AccountCountMismatch
    );

    let target_version = org.permissions_version;
    let org_key = ctx.accounts.organization.key();

    let authority_info = ctx.accounts.authority.to_account_info();
    let system_program_info = ctx.accounts.system_program.to_account_info();
    // Pre-clone the org AccountInfo so we can use it as a lamport relay inside
    // the loop without mixing lifetimes from ctx.accounts and remaining_accounts.
    let org_account_info = ctx.accounts.organization.to_account_info();

    let perm_accounts = &ctx.remaining_accounts[..pcc];
    let remaining = &ctx.remaining_accounts[pcc..];
    let mut offset: usize = 0;
    // Track processed user pubkeys to prevent duplicate accounts from
    // artificially decrementing users_pending_recompute below the real count.
    let mut processed_users: std::collections::BTreeSet<Pubkey> = std::collections::BTreeSet::new();

    // Index perm chunks once for O(1) lookups.
    let perm_index = if pcc > 0 {
        Some(build_perm_chunk_index(perm_accounts, &org_key, ctx.program_id)?)
    } else {
        None
    };

    for &chunk_count in user_chunk_counts.iter() {
        // Need at least UA + UPC.
        require!(offset + 1 < remaining.len(), RbacError::AccountCountMismatch);

        let ua_info = &remaining[offset];
        let upc_info = &remaining[offset + 1];
        offset += 2;

        require!(ua_info.owner == ctx.program_id, RbacError::MissingAuthProof);
        require!(ua_info.is_writable, RbacError::MissingAuthProof);
        require!(upc_info.owner == ctx.program_id, RbacError::MissingAuthProof);
        require!(upc_info.is_writable, RbacError::MissingAuthProof);

        let cc = chunk_count as usize;
        require!(offset + cc <= remaining.len(), RbacError::AccountCountMismatch);

        // Slice of chunk accounts for this user.
        let user_chunks = &remaining[offset..offset + cc];
        offset += cc;

        // Index this user's role chunks once for O(1) lookups.
        let role_index = build_role_chunk_index(user_chunks, &org_key, ctx.program_id)?;

        let mut ua = {
            let data = ua_info
                .try_borrow_data()
                .map_err(|_| error!(RbacError::MissingAuthProof))?;
            UserAccount::try_deserialize(&mut data.as_ref())
                .map_err(|_| error!(RbacError::MissingAuthProof))?
        };

        require!(ua.organization == org_key, RbacError::MissingAuthProof);

        // Verify UA PDA using the stored bump to prevent a spoofed account
        // from satisfying the completeness counter without updating a real member.
        let expected_ua_pda = Pubkey::create_program_address(
            &[b"user_account", org_key.as_ref(), ua.user.as_ref(), &[ua.bump]],
            ctx.program_id,
        ).map_err(|_| error!(RbacError::MissingAuthProof))?;
        require!(ua_info.key() == expected_ua_pda, RbacError::MissingAuthProof);

        // Reject duplicate users within the same batch call — each member must
        // be counted once. This check must precede the cached_version guard so
        // that same-batch duplicates get AccountCountMismatch: the first
        // iteration writes cached_version = target_version back to the account,
        // so a second iteration for the same account would otherwise hit
        // AlreadyRecomputed instead.
        require!(
            processed_users.insert(ua.user),
            RbacError::AccountCountMismatch
        );

        // Reject users already processed in a prior batch call — prevents the
        // same user appearing across separate calls from artificially
        // decrementing users_pending_recompute below the real unprocessed count.
        require!(
            ua.cached_version < target_version,
            RbacError::AlreadyRecomputed
        );

        // Recompute: filter direct_permissions (active only) ∪ each assigned role's effective_permissions.
        let mut result: Vec<u8> = Vec::new();

        // Include only active direct permissions.
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
                        // inactive permission — silently dropped
                    } else {
                        // No perm chunks passed — include bit as-is.
                        set_bit(&mut result, perm_index_val);
                    }
                }
            }
        }

        let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(ua.assigned_roles.len());
        // Only track roles that are currently active so effective_roles doesn't
        // keep a bit set for soft-deleted roles after a recompute cycle.
        let mut active_role_indices: Vec<u32> = Vec::with_capacity(ua.assigned_roles.len());

        for role_ref in ua.assigned_roles.iter() {
            let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
            let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
            let chunk = role_index
                .get(&chunk_idx)
                .ok_or(RbacError::ChunkNotFound)?;
            require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
            let entry = &chunk.entries[slot];
            require!(entry.topo_index == role_ref.topo_index, RbacError::RoleSlotEmpty);
            if entry.active {
                active_role_indices.push(role_ref.topo_index);
                // Filter the role's effective_permissions through PermChunk active status,
                // identical to how we filter direct_permissions above. This guarantees
                // on-chain consistency: deleted permissions are dropped regardless of
                // whether the role itself was recomputed in this update cycle.
                for (byte_idx, &byte) in entry.effective_permissions.iter().enumerate() {
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

        for role_ref in ua.assigned_roles.iter_mut() {
            if let Some(&(_, v)) = new_versions.iter().find(|(ti, _)| *ti == role_ref.topo_index) {
                role_ref.last_seen_version = v;
            }
        }

        ua.effective_permissions = result;
        ua.cached_version = target_version;

        let new_space = ua.current_size();
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(new_space);
        let current_lamports = ua_info.lamports();
        if current_lamports < new_min {
            let diff = new_min - current_lamports;
            // We cannot CPI directly from authority → ua_info because they come
            // from different Context fields (accounts vs remaining_accounts) whose
            // lifetimes the compiler treats as distinct in the #[program] macro
            // dispatch. Instead we relay through the org account:
            //   Step 1: CPI authority → org  (both in ctx.accounts, same 'info ✓)
            //   Step 2: direct org → ua      (org is program-owned → can decrease ✓)
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    system_program_info.clone(),
                    anchor_lang::system_program::Transfer {
                        from: authority_info.clone(),
                        to: org_account_info.clone(),
                    },
                ),
                diff,
            )?;
            **org_account_info.try_borrow_mut_lamports()? -= diff;
            **ua_info.try_borrow_mut_lamports()? += diff;
        }
        ua_info.resize(new_space)?;
        // Reclaim excess lamports when UA shrinks (e.g. after a
        // permission-deletion cycle reduces effective_permissions length).
        // ua is program-owned (can decrease ✓); increasing authority is always OK ✓.
        let current_lamports_after = ua_info.lamports();
        if current_lamports_after > new_min {
            let excess = current_lamports_after - new_min;
            **ua_info.try_borrow_mut_lamports()? -= excess;
            **authority_info.try_borrow_mut_lamports()? += excess;
        }

        let mut ua_data = ua_info
            .try_borrow_mut_data()
            .map_err(|_| error!(RbacError::MissingAuthProof))?;
        let mut cursor = std::io::Cursor::new(ua_data.as_mut());
        ua.try_serialize(&mut cursor)?;
        drop(ua_data);

        // Deserialize, update, and re-serialize the UserPermCache.
        let mut cache = {
            let data = upc_info
                .try_borrow_data()
                .map_err(|_| error!(RbacError::MissingAuthProof))?;
            UserPermCache::try_deserialize(&mut data.as_ref())
                .map_err(|_| error!(RbacError::MissingAuthProof))?
        };

        // Verify UPC PDA using the stored bump.
        let expected_upc_pda = Pubkey::create_program_address(
            &[b"user_perm_cache", org_key.as_ref(), ua.user.as_ref(), &[cache.bump]],
            ctx.program_id,
        ).map_err(|_| error!(RbacError::MissingAuthProof))?;
        require!(upc_info.key() == expected_upc_pda, RbacError::MissingAuthProof);

        copy_to_fixed(&mut cache.effective_permissions, &ua.effective_permissions);
        // Only set bits for active roles — soft-deleted roles that remain in
        // ua.assigned_roles must not appear in effective_roles, otherwise
        // has_role returns true for a role that has been globally deleted.
        cache.effective_roles = [0u8; 32];
        for topo_index in &active_role_indices {
            set_bit_arr(&mut cache.effective_roles, *topo_index);
        }
        cache.permissions_version = target_version;

        let mut upc_data = upc_info
            .try_borrow_mut_data()
            .map_err(|_| error!(RbacError::MissingAuthProof))?;
        let mut cursor = std::io::Cursor::new(upc_data.as_mut());
        cache.try_serialize(&mut cursor)?;
    }

    require!(offset == remaining.len(), RbacError::AccountCountMismatch);

    // Decrement the user recompute counter by the number of users processed
    // in this batch so finish_update can enforce completeness.
    let users_processed = u32::try_from(user_chunk_counts.len())
        .map_err(|_| error!(RbacError::AccountCountMismatch))?;
    let org = &mut ctx.accounts.organization;
    org.users_pending_recompute = org
        .users_pending_recompute
        .checked_sub(users_processed)
        .ok_or(error!(RbacError::UpdateIncomplete))?;

    Ok(())
}
