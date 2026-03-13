use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

/// Deletes a resource. The caller must have the specified permission.
#[derive(Accounts)]
pub struct DeleteResource<'info> {
    #[account(
        mut,
        close = resource_creator,
        seeds = [
            b"resource",
            organization.key().as_ref(),
            resource_creator.key().as_ref(),
            &resource.resource_id.to_le_bytes(),
        ],
        bump = resource.bump,
        constraint = resource.organization == organization.key(),
    )]
    pub resource: Account<'info, Resource>,

    #[account(
        seeds = [b"organization", organization.original_admin.as_ref(), organization.name.as_bytes()],
        bump = organization.bump,
    )]
    pub organization: Account<'info, Organization>,

    #[account(
        seeds = [
            b"user_perm_cache",
            organization.key().as_ref(),
            authority.key().as_ref(),
        ],
        bump = user_perm_cache.bump,
        constraint = user_perm_cache.organization == organization.key(),
        constraint = user_perm_cache.user == authority.key(),
    )]
    pub user_perm_cache: Account<'info, UserPermCache>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Receives the rent lamports when the resource is closed.
    /// Must match the pubkey stored in resource.creator.
    #[account(
        mut,
        constraint = resource_creator.key() == resource.creator @ RbacError::NotResourceCreator,
    )]
    pub resource_creator: SystemAccount<'info>,
}

/// remaining_accounts layout:
///   [0] — PermChunk PDA for `resource.required_permission / PERMS_PER_CHUNK`.
///          Required in both the normal and recovery paths so the handler can
///          inspect the permission's active flag.
pub fn handler(ctx: Context<DeleteResource>) -> Result<()> {
    let cache = &ctx.accounts.user_perm_cache;
    let org = &ctx.accounts.organization;
    // Use the permission index stored at creation time — the caller cannot
    // self-select a weaker permission to bypass the access check.
    let required_permission = ctx.accounts.resource.required_permission;
    let org_key = org.key();

    require!(org.state == OrgState::Idle, RbacError::OrgNotIdle);

    // The caller must pass the PermChunk for required_permission in
    // remaining_accounts[0] so the handler can read the active flag.
    // find_perm_chunk_in_accounts verifies the PDA (seeds + bump) before
    // returning the deserialized chunk, preventing spoofed accounts.
    require!(!ctx.remaining_accounts.is_empty(), RbacError::AccountCountMismatch);
    let chunk_idx = required_permission / PERMS_PER_CHUNK as u32;
    let perm_chunk = find_perm_chunk_in_accounts(
        ctx.remaining_accounts,
        &org_key,
        chunk_idx,
        ctx.program_id,
    )?;

    let perm_slot = required_permission as usize % PERMS_PER_CHUNK;
    let perm_is_active = perm_slot < perm_chunk.entries.len()
        && perm_chunk.entries[perm_slot].index == required_permission
        && perm_chunk.entries[perm_slot].active;

    if perm_is_active {
        // Normal path: permission is still active — caller must hold it in
        // a fresh UserPermCache.
        require!(
            cache.permissions_version >= org.permissions_version,
            RbacError::StalePermissions
        );
        require!(
            has_bit(&cache.effective_permissions, required_permission),
            RbacError::InsufficientPermission
        );
    } else {
        // Recovery path: required_permission has been soft-deleted.
        // No user's fresh cache can ever contain a deleted permission bit,
        // so the normal check would permanently block deletion and lock the
        // creator's rent in the resource account forever.
        // Only the original creator (as authority/signer) may force-close
        // their own orphaned resource; third parties cannot trigger this.
        // Lamports flow to resource_creator via `close = resource_creator`.
        require!(
            ctx.accounts.authority.key() == ctx.accounts.resource.creator,
            RbacError::NotResourceCreator
        );
    }

    msg!(
        "Resource '{}' (id={}) deleted by {}",
        ctx.accounts.resource.title,
        ctx.accounts.resource.resource_id,
        ctx.accounts.authority.key()
    );
    Ok(())
}
