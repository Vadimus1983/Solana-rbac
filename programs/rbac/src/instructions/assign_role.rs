use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Assign a role to a user. Works in **Idle** state — no batch recompute needed.
///
/// The role's current `effective_permissions` are filtered through the supplied
/// PermChunk accounts and then unioned into the user's `effective_permissions`
/// inline. `cached_version` is refreshed immediately.
/// The `UserPermCache` is also updated in the same transaction.
///
/// Authorization: super_admin OR a delegated caller whose UserPermCache PDA
/// (verified via find_program_address) has MANAGE_ROLES_PERMISSION_INDEX set
/// and a fresh `permissions_version`.
///
/// remaining_accounts layout:
///   super_admin path: [perm_chunks (0..perm_chunk_count)]
///   delegated path:   [caller_cache, perm_chunks (1..1+perm_chunk_count)]
#[derive(Accounts)]
#[instruction(role_index: u32)]
pub struct AssignRole<'info> {
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

    /// The chunk containing the role to assign (readonly).
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
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<AssignRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
    let org = &ctx.accounts.organization;
    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    let org_key = org.key();
    let org_permissions_version = org.permissions_version;

    // Authorization: super_admin OR delegated caller with MANAGE_ROLES_PERMISSION_INDEX.
    let base_offset: usize;
    if ctx.accounts.authority.key() != org.super_admin {
        require!(!ctx.remaining_accounts.is_empty(), RbacError::NotSuperAdmin);

        let cache_info = &ctx.remaining_accounts[0];
        require!(cache_info.owner == ctx.program_id, RbacError::NotSuperAdmin);

        // Verify the PDA derivation to prevent a caller from supplying
        // a UserPermCache that belongs to a different organization.
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

    // Index perm chunks once for O(1) lookups.
    let perm_index = if pcc > 0 {
        Some(build_perm_chunk_index(perm_accounts, &org_key, ctx.program_id)?)
    } else {
        None
    };

    // Read role entry data (clone to avoid borrow conflicts with user_account).
    let slot = role_index as usize % ROLES_PER_CHUNK;
    let chunk = &ctx.accounts.role_chunk;
    require!(slot < chunk.entries.len(), RbacError::RoleSlotEmpty);
    let entry = &chunk.entries[slot];
    require!(entry.topo_index == role_index, RbacError::RoleSlotEmpty);
    require!(entry.active, RbacError::RoleInactive);
    let entry_version = entry.version;
    let raw_effective = entry.effective_permissions.clone();

    // Filter the role's effective_permissions through PermChunks to drop any
    // bits left over from soft-deleted permissions that were not yet cleaned
    // up by a recompute_role call in the current update cycle.
    let entry_effective: Vec<u8> = if pcc > 0 {
        let mut filtered = Vec::new();
        for (byte_idx, &byte) in raw_effective.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit in 0..8u32 {
                if byte & (1 << bit) != 0 {
                    let perm_index_val = (byte_idx as u32) * 8 + bit;
                    let perm_chunk_idx = perm_index_val / PERMS_PER_CHUNK as u32;
                    let perm_slot = perm_index_val as usize % PERMS_PER_CHUNK;
                    if let Some(perm_chunk) =
                        perm_index.as_ref().and_then(|idx| idx.get(&perm_chunk_idx))
                    {
                        if perm_slot < perm_chunk.entries.len()
                            && perm_chunk.entries[perm_slot].index == perm_index_val
                            && perm_chunk.entries[perm_slot].active
                        {
                            set_bit(&mut filtered, perm_index_val);
                        }
                    }
                }
            }
        }
        filtered
    } else {
        // pcc == 0: no PermChunks supplied — trust the stored effective_permissions.
        // Safe in Idle state: commit_update enforces roles_pending_recompute == 0
        // before the cycle closes, so all roles are freshly recomputed and their
        // effective_permissions can no longer contain deleted-permission bits.
        raw_effective
    };

    let ua = &mut ctx.accounts.user_account;
    require!(
        !ua.assigned_roles.iter().any(|r| r.topo_index == role_index),
        RbacError::RoleAlreadyAssigned
    );

    // Inline recompute: union this role's effective_permissions into the user's.
    let new_effective = bitmask_union(&ua.effective_permissions, &entry_effective);
    ua.assigned_roles.push(RoleRef {
        topo_index: role_index,
        last_seen_version: entry_version,
    });
    ua.effective_permissions = new_effective;
    ua.cached_version = org_permissions_version;

    // Realloc: +12 bytes (RoleRef) + possible effective_permissions growth.
    let new_space = ua.current_size();
    let rent = Rent::get()?;
    let new_min = rent.minimum_balance(new_space);
    let current_lamports = ua.to_account_info().lamports();
    if current_lamports < new_min {
        let diff = new_min - current_lamports;
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: ua.to_account_info(),
                },
            ),
            diff,
        )?;
    }
    ua.to_account_info().resize(new_space)?;

    // Sync UserPermCache.
    let cache = &mut ctx.accounts.user_perm_cache;
    bitmask_union_into(&mut cache.effective_permissions, &entry_effective);
    set_bit_arr(&mut cache.effective_roles, role_index);
    cache.permissions_version = org_permissions_version;

    emit!(RoleAssigned {
        organization: ctx.accounts.organization.key(),
        user: ctx.accounts.user_account.user,
        role_index,
    });

    msg!("Role index {} assigned to user {}", role_index, ctx.accounts.user_account.user);
    Ok(())
}
