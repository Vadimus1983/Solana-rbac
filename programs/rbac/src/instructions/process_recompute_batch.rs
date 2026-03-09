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
        seeds = [b"organization", organization.name.as_bytes()],
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

    let target_version = ctx.accounts.organization.permissions_version;
    let org_key = ctx.accounts.organization.key();

    let pcc = perm_chunk_count as usize;
    let perm_accounts = &ctx.remaining_accounts[..pcc];
    let remaining = &ctx.remaining_accounts[pcc..];
    let mut offset: usize = 0;

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

        let mut ua = {
            let data = ua_info
                .try_borrow_data()
                .map_err(|_| error!(RbacError::MissingAuthProof))?;
            UserAccount::try_deserialize(&mut data.as_ref())
                .map_err(|_| error!(RbacError::MissingAuthProof))?
        };

        require!(ua.organization == org_key, RbacError::MissingAuthProof);

        // Recompute: filter direct_permissions (active only) ∪ each assigned role's effective_permissions.
        let mut result: Vec<u8> = Vec::new();

        // Include only active direct permissions.
        for (byte_idx, &byte) in ua.direct_permissions.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let perm_index = (byte_idx as u32) * 8 + bit;
                    let perm_chunk_idx = perm_index / PERMS_PER_CHUNK as u32;
                    let perm_slot = perm_index as usize % PERMS_PER_CHUNK;
                    if pcc > 0 {
                        let perm_chunk = find_perm_chunk_in_accounts(
                            perm_accounts,
                            &org_key,
                            perm_chunk_idx,
                            ctx.program_id,
                        )?;
                        if perm_slot < perm_chunk.entries.len()
                            && perm_chunk.entries[perm_slot].index == perm_index
                            && perm_chunk.entries[perm_slot].active
                        {
                            set_bit(&mut result, perm_index);
                        }
                        // inactive permission — silently dropped
                    } else {
                        // No perm chunks passed — include bit as-is.
                        set_bit(&mut result, perm_index);
                    }
                }
            }
        }

        let mut new_versions: Vec<(u32, u64)> = Vec::with_capacity(ua.assigned_roles.len());

        for role_ref in ua.assigned_roles.iter() {
            let chunk_idx = role_ref.topo_index / ROLES_PER_CHUNK as u32;
            let slot = role_ref.topo_index as usize % ROLES_PER_CHUNK;
            let chunk = find_role_chunk_in_accounts(user_chunks, &org_key, chunk_idx, ctx.program_id)?;
            let entry = &chunk.entries[slot];
            if entry.active {
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
                            let perm_index = (byte_idx as u32) * 8 + bit;
                            let perm_chunk_idx = perm_index / PERMS_PER_CHUNK as u32;
                            let perm_slot = perm_index as usize % PERMS_PER_CHUNK;
                            if pcc > 0 {
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
            let from = ctx.accounts.authority.to_account_info();
            **from.try_borrow_mut_lamports()? -= diff;
            **ua_info.try_borrow_mut_lamports()? += diff;
        }
        ua_info.resize(new_space)?;

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

        copy_to_fixed(&mut cache.effective_permissions, &ua.effective_permissions);
        cache.effective_roles = [0u8; 32];
        for rr in &ua.assigned_roles {
            set_bit_arr(&mut cache.effective_roles, rr.topo_index);
        }
        cache.permissions_version = target_version;

        let mut upc_data = upc_info
            .try_borrow_mut_data()
            .map_err(|_| error!(RbacError::MissingAuthProof))?;
        let mut cursor = std::io::Cursor::new(upc_data.as_mut());
        cache.try_serialize(&mut cursor)?;
    }

    require!(offset == remaining.len(), RbacError::AccountCountMismatch);

    // Issue #8: decrement the user recompute counter by the number of users
    // processed in this batch so finish_update can enforce completeness.
    let users_processed = user_chunk_counts.len() as u32;
    let org = &mut ctx.accounts.organization;
    org.users_pending_recompute = org.users_pending_recompute.saturating_sub(users_processed);

    Ok(())
}
