use anchor_lang::prelude::*;
use solana_security_txt::security_txt;

pub mod errors;
pub mod macros;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("H4yTMpUrSrb5Etr2FXhoC8NwaGaigLa2B3KpLZtnv9Lf");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Solana RBAC",
    project_url: "https://github.com/Vadimus1983/Solana-rbac",
    contacts: "email:vadym.prygoda@gmail.com,link:https://github.com/Vadimus1983/Solana-rbac/issues",
    policy: "https://github.com/Vadimus1983/Solana-rbac/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/Vadimus1983/Solana-rbac"
}

#[program]
pub mod rbac {
    use super::*;

    // ── Organization ────────────────────────────────────────────────────

    pub fn initialize_organization(
        ctx: Context<InitializeOrganization>,
        name: String,
        manage_roles_permission: u32,
    ) -> Result<()> {
        instructions::initialize_org::handler(ctx, name, manage_roles_permission)
    }

    // ── State machine ───────────────────────────────────────────────────

    pub fn begin_update(ctx: Context<BeginUpdate>) -> Result<()> {
        instructions::begin_update::handler(ctx)
    }

    pub fn commit_update(ctx: Context<CommitUpdate>) -> Result<()> {
        instructions::commit_update::handler(ctx)
    }

    pub fn finish_update(ctx: Context<FinishUpdate>) -> Result<()> {
        instructions::finish_update::handler(ctx)
    }

    pub fn cancel_update(ctx: Context<CancelUpdate>) -> Result<()> {
        instructions::cancel_update::handler(ctx)
    }

    // ── Permissions ─────────────────────────────────────────────────────

    pub fn create_permission(
        ctx: Context<CreatePermission>,
        name: String,
        description: String,
    ) -> Result<()> {
        instructions::create_permission::handler(ctx, name, description)
    }

    pub fn delete_permission(ctx: Context<DeletePermission>, perm_index: u32) -> Result<()> {
        instructions::delete_permission::handler(ctx, perm_index)
    }

    // ── Roles ───────────────────────────────────────────────────────────

    pub fn create_role(
        ctx: Context<CreateRole>,
        name: String,
        description: String,
    ) -> Result<()> {
        instructions::create_role::handler(ctx, name, description)
    }

    pub fn delete_role(ctx: Context<DeleteRole>, role_index: u32) -> Result<()> {
        instructions::delete_role::handler(ctx, role_index)
    }

    pub fn add_role_permission(
        ctx: Context<AddRolePermission>,
        role_index: u32,
        permission_index: u32,
    ) -> Result<()> {
        instructions::add_role_permission::handler(ctx, role_index, permission_index)
    }

    pub fn remove_role_permission(
        ctx: Context<RemoveRolePermission>,
        role_index: u32,
        permission_index: u32,
    ) -> Result<()> {
        instructions::remove_role_permission::handler(ctx, role_index, permission_index)
    }

    pub fn add_child_role(
        ctx: Context<AddChildRole>,
        parent_index: u32,
        child_index: u32,
    ) -> Result<()> {
        instructions::add_child_role::handler(ctx, parent_index, child_index)
    }

    pub fn remove_child_role(
        ctx: Context<RemoveChildRole>,
        parent_index: u32,
        child_index: u32,
    ) -> Result<()> {
        instructions::remove_child_role::handler(ctx, parent_index, child_index)
    }

    pub fn recompute_role(ctx: Context<RecomputeRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
        instructions::recompute_role::handler(ctx, role_index, perm_chunk_count)
    }

    // ── Users ───────────────────────────────────────────────────────────

    pub fn create_user_account(ctx: Context<CreateUserAccount>) -> Result<()> {
        instructions::create_user_account::handler(ctx)
    }

    pub fn close_user_account(ctx: Context<CloseUserAccount>) -> Result<()> {
        instructions::close_user_account::handler(ctx)
    }

    pub fn assign_role(ctx: Context<AssignRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
        instructions::assign_role::handler(ctx, role_index, perm_chunk_count)
    }

    pub fn revoke_role(ctx: Context<RevokeRole>, role_index: u32, perm_chunk_count: u8) -> Result<()> {
        instructions::revoke_role::handler(ctx, role_index, perm_chunk_count)
    }

    pub fn assign_user_permission(
        ctx: Context<AssignUserPermission>,
        permission_index: u32,
    ) -> Result<()> {
        instructions::assign_user_permission::handler(ctx, permission_index)
    }

    pub fn revoke_user_permission(
        ctx: Context<RevokeUserPermission>,
        permission_index: u32,
        perm_chunk_count: u8,
    ) -> Result<()> {
        instructions::revoke_user_permission::handler(ctx, permission_index, perm_chunk_count)
    }

    // ── Batch recompute ─────────────────────────────────────────────────

    pub fn process_recompute_batch(
        ctx: Context<ProcessRecomputeBatch>,
        user_chunk_counts: Vec<u8>,
        perm_chunk_count: u8,
    ) -> Result<()> {
        instructions::process_recompute_batch::handler(ctx, user_chunk_counts, perm_chunk_count)
    }

    // ── Verification (read-only) ────────────────────────────────────────

    pub fn has_permission(
        ctx: Context<HasPermission>,
        permission_index: u32,
    ) -> Result<()> {
        instructions::has_permission::handler(ctx, permission_index)
    }

    pub fn has_role(ctx: Context<HasRole>, role_index: u32) -> Result<()> {
        instructions::has_role::handler(ctx, role_index)
    }

    // ── Demo resources ──────────────────────────────────────────────────

    pub fn create_resource(
        ctx: Context<CreateResource>,
        title: String,
        resource_id: u64,
        required_permission: u32,
    ) -> Result<()> {
        instructions::create_resource::handler(ctx, title, resource_id, required_permission)
    }

    pub fn delete_resource(ctx: Context<DeleteResource>) -> Result<()> {
        instructions::delete_resource::handler(ctx)
    }

    pub fn transfer_super_admin(ctx: Context<TransferSuperAdmin>) -> Result<()> {
        instructions::transfer_super_admin::handler(ctx)
    }
}
