use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Recomputes a role's `effective_permissions` from its `direct_permissions`
/// (filtered to only active permissions) and the `effective_permissions` of
/// all its direct children.
///
/// `perm_chunk_count` — number of PermChunk accounts at the START of
/// `remaining_accounts` used to validate active status of direct permissions.
/// Pass 0 if the role has no direct permissions.
///
/// remaining_accounts layout:
///   [0 .. perm_chunk_count)  — readonly PermChunk accounts (deduplicated by chunk index)
///   [perm_chunk_count ..)    — readonly RoleChunk accounts for cross-chunk children
#[derive(Accounts)]
#[instruction(role_index: u32)]
pub struct RecomputeRole<'info> {
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

pub fn handler(ctx: Context<RecomputeRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
    require!(
        ctx.accounts.organization.state == OrgState::Updating,
        RbacError::OrgNotInUpdateMode
    );

    let parent_chunk_idx = role_index / ROLES_PER_CHUNK as u32;
    let slot = role_index as usize % ROLES_PER_CHUNK;
    let org_key = ctx.accounts.organization.key();

    {
        let chunk = &ctx.accounts.role_chunk;
        require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
        let entry = &chunk.entries[slot];
        require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
        require!(entry.active, RbacError::RoleInactive);
        // Idempotency guard: prevent double-decrementing roles_pending_recompute
        // by re-running recompute_role on the same role in one update cycle.
        require!(
            entry.recompute_epoch != ctx.accounts.organization.permissions_version,
            RbacError::AlreadyRecomputed
        );
    }

    let children: Vec<u32> = ctx.accounts.role_chunk.entries[slot].children.clone();
    let direct_perms: Vec<u8> = ctx.accounts.role_chunk.entries[slot].direct_permissions.clone();

    let pcc = perm_chunk_count as usize;
    require!(
        pcc <= ctx.remaining_accounts.len(),
        RbacError::AccountCountMismatch
    );
    let perm_accounts = &ctx.remaining_accounts[..pcc];
    let role_accounts = &ctx.remaining_accounts[pcc..];

    // Index chunks once for O(1) lookups.
    let perm_index = if pcc > 0 {
        Some(build_perm_chunk_index(perm_accounts, &org_key, ctx.program_id)?)
    } else {
        None
    };
    let role_chunk_index = build_role_chunk_index(role_accounts, &org_key, ctx.program_id)?;

    let org_permissions_version = ctx.accounts.organization.permissions_version;
    // Enforce topological order: every child must have been recomputed this cycle before this parent.
    for &child_topo in &children {
        let child_chunk_idx = child_topo / ROLES_PER_CHUNK as u32;
        let child_slot = child_topo as usize % ROLES_PER_CHUNK;
        let child_recompute_epoch = if child_chunk_idx == parent_chunk_idx {
            let chunk = &ctx.accounts.role_chunk;
            if child_slot < chunk.entries.len() {
                let ce = &chunk.entries[child_slot];
                if ce.active && ce.topo_index == child_topo {
                    ce.recompute_epoch
                } else {
                    continue; // inactive or slot empty, skip check
                }
            } else {
                continue;
            }
        } else {
            let child_chunk = role_chunk_index
                .get(&child_chunk_idx)
                .ok_or(RbacError::ChunkNotFound)?;
            if child_slot < child_chunk.entries.len() {
                let ce = &child_chunk.entries[child_slot];
                if ce.active && ce.topo_index == child_topo {
                    ce.recompute_epoch
                } else {
                    continue;
                }
            } else {
                continue;
            }
        };
        require!(
            child_recompute_epoch == org_permissions_version,
            RbacError::ChildRoleNotRecomputed
        );
    }

    // Build effective_permissions starting from direct_permissions,
    // but only include bits whose corresponding PermEntry is still active.
    let mut result: Vec<u8> = Vec::new();
    for (byte_idx, &byte) in direct_perms.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                let perm_index_val = (byte_idx as u32) * 8 + bit;
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
                // If inactive or not found in entries — bit is silently dropped.
            }
        }
    }

    // Union each child's effective_permissions into result, filtered through
    // PermChunks to prevent stale/deleted permission bits inherited from
    // children that have not yet been recomputed in this update cycle.
    for &child_topo in &children {
        let child_chunk_idx = child_topo / ROLES_PER_CHUNK as u32;
        let child_slot = child_topo as usize % ROLES_PER_CHUNK;

        let child_eff: Vec<u8> = if child_chunk_idx == parent_chunk_idx {
            let chunk = &ctx.accounts.role_chunk;
            if child_slot < chunk.entries.len() {
                let ce = &chunk.entries[child_slot];
                if ce.active && ce.topo_index == child_topo {
                    ce.effective_permissions.clone()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            let child_chunk = role_chunk_index
                .get(&child_chunk_idx)
                .ok_or(RbacError::ChunkNotFound)?;
            if child_slot < child_chunk.entries.len() {
                let ce = &child_chunk.entries[child_slot];
                if ce.active && ce.topo_index == child_topo {
                    ce.effective_permissions.clone()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };

        // Filter child_eff through PermChunks before merging — same approach
        // as for direct_permissions above.
        for (byte_idx, &byte) in child_eff.iter().enumerate() {
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
                        // pcc == 0: trust the child's stored effective_permissions.
                        // Safe: topological ordering ensures children were freshly
                        // recomputed this cycle (recompute_epoch == permissions_version),
                        // so their effective_permissions are clean.
                        set_bit(&mut result, perm_index_val);
                    }
                }
            }
        }
    }

    // Build pruned children list — remove entries for inactive or missing roles
    // so dead references don't permanently consume MAX_CHILDREN_PER_ROLE slots.
    let mut new_children: Vec<u32> = Vec::new();
    for &child_topo in &children {
        let child_chunk_idx = child_topo / ROLES_PER_CHUNK as u32;
        let child_slot = child_topo as usize % ROLES_PER_CHUNK;
        let is_active = if child_chunk_idx == parent_chunk_idx {
            let chunk = &ctx.accounts.role_chunk;
            child_slot < chunk.entries.len()
                && chunk.entries[child_slot].active
                && chunk.entries[child_slot].topo_index == child_topo
        } else {
            role_chunk_index
                .get(&child_chunk_idx)
                .map_or(false, |chunk| {
                    child_slot < chunk.entries.len()
                        && chunk.entries[child_slot].active
                        && chunk.entries[child_slot].topo_index == child_topo
                })
        };
        if is_active {
            new_children.push(child_topo);
        }
    }

    // Combined size delta: effective_permissions change + children Vec change.
    let old_eff_len = ctx.accounts.role_chunk.entries[slot].effective_permissions.len();
    let old_children_count = ctx.accounts.role_chunk.entries[slot].children.len();
    let new_eff_len = result.len();
    let new_children_count = new_children.len();
    let delta: isize = (new_eff_len as isize - old_eff_len as isize)
        + ((new_children_count as isize - old_children_count as isize) * 4);

    let current_len = ctx.accounts.role_chunk.to_account_info().data_len();
    let new_space = (current_len as isize + delta) as usize;
    if delta > 0 {
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
    } else if delta < 0 {
        ctx.accounts.role_chunk.to_account_info().resize(new_space)?;
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(new_space);
        let current_lamports = ctx.accounts.role_chunk.to_account_info().lamports();
        if current_lamports > new_min {
            let excess = current_lamports - new_min;
            **ctx.accounts.role_chunk.to_account_info().try_borrow_mut_lamports()? -= excess;
            **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += excess;
        }
    }

    let entry = &mut ctx.accounts.role_chunk.entries[slot];
    entry.effective_permissions = result;
    entry.children = new_children;
    entry.version += 1;
    entry.recompute_epoch = org_permissions_version;

    // Decrement the recompute counter so commit_update can enforce that all
    // active roles were processed before closing the update cycle.
    let org = &mut ctx.accounts.organization;
    org.roles_pending_recompute = org.roles_pending_recompute.saturating_sub(1);

    msg!("Role index {} effective_permissions recomputed ({} roles remaining)", role_index, org.roles_pending_recompute);
    Ok(())
}
