# Solana RBAC

A production-grade **Role-Based Access Control** system implemented as a Solana on-chain program in Rust using the [Anchor](https://www.anchor-lang.com/) framework.

Organisations, roles, permissions, and user accounts all live on-chain. Permission checks are a single bitmask read — O(1) regardless of how many roles a user holds.

---

## Features

- **Multi-tenant** — one deployed program, unlimited independent organisations
- **Role hierarchy** — roles inherit permissions from child roles (DAG, cycle-safe by construction)
- **Permission bitmask** — up to 256 permissions per org, stored as a compact `Vec<u8>` or fixed `[u8; 32]`
- **Hot-path cache** — `UserPermCache` (145 bytes, fixed size) enables O(1) on-chain CPI checks
- **Chunked storage** — roles split into 16-entry chunks, permissions into 32-entry chunks; accounts grow on demand via `realloc`
- **Governed state machine** — schema changes are atomic: `begin_update → [edit] → commit_update → [recompute] → finish_update`
- **Delegation** — any user holding permission index `3` (`MANAGE_ROLES`) can assign/revoke roles without being super_admin
- **CPI-ready** — `has_permission` and `has_role` are callable from other programs with automatic TX revert on failure
- **Demo resources** — built-in `Resource` account type shows permission-gated creation/deletion

---

## Program IDs

| Network  | Program ID |
|----------|------------|
| Localnet | `H4yTMpUrSrb5Etr2FXhoC8NwaGaigLa2B3KpLZtnv9Lf` |
| Devnet   | `Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS` |

---

## Repository Layout

```
Solana-rbac/
├── programs/rbac/src/        # Anchor program (Rust)
│   ├── lib.rs                # Instruction router
│   ├── state.rs              # Account structs, bitmask helpers, events
│   ├── errors.rs             # Custom error codes
│   ├── macros.rs             # Shared macros
│   └── instructions/         # One file per instruction
├── tests/                    # TypeScript integration tests (Mocha)
├── admin/                    # Browser admin panel (React + Vite + Tailwind)
│   └── src/
│       ├── lib/              # pda.ts, bitmask.ts, program.ts, constants.ts
│       ├── pages/            # Overview, Permissions, Roles, Users
│       └── components/       # WalletButton, StateMachineBar, TxToast, Modal
├── docs/
│   └── architecture.md       # Mermaid diagrams: data model, flows, auth matrix
├── Anchor.toml
└── Cargo.toml
```

---

## Account Model

| Account | PDA Seeds | Description |
|---------|-----------|-------------|
| `Organization` | `["organization", original_admin, name]` | Root account; holds state machine, counters. Address stable across `transfer_super_admin`. |
| `RoleChunk` | `["role_chunk", org, chunk_index_le4]` | Holds up to 16 `RoleEntry` structs |
| `PermChunk` | `["perm_chunk", org, chunk_index_le4]` | Holds up to 32 `PermEntry` structs |
| `UserAccount` | `["user_account", org, user]` | Assigned roles + permission bitmasks (dynamic size) |
| `UserPermCache` | `["user_perm_cache", org, user]` | Fixed 145-byte hot-path cache, mirrored from UserAccount |
| `Resource` | `["resource", org, creator, resource_id_le8]` | Demo permission-gated resource; one per (org, creator, resource_id) |

### Chunk index arithmetic

```
Role N   → chunk[N / 16].entries[N % 16]   (ROLES_PER_CHUNK = 16)
Perm N   → chunk[N / 32].entries[N % 32]   (PERMS_PER_CHUNK = 32)
```

---

## State Machine

```
Idle ──(begin_update)──► Updating ──(commit_update)──► Recomputing ──(finish_update)──► Idle
```

| State | Allowed operations |
|-------|--------------------|
| **Idle** | `create_user_account`, `assign_role`, `revoke_role`, `assign_user_permission`, `revoke_user_permission`, `has_role`, `has_permission`, `create_resource`, `delete_resource` |
| **Updating** | `create_role`, `delete_role`, `create_permission`, `delete_permission`, `add_role_permission`, `remove_role_permission`, `add_child_role`, `remove_child_role`, `recompute_role` |
| **Recomputing** | `process_recompute_batch` |

`commit_update` bumps `Organization.permissions_version`, marking all cached user permissions as stale. `finish_update` returns to Idle after all user caches have been refreshed.

---

## Instructions

### Organisation

| Instruction | Auth | Notes |
|-------------|------|-------|
| `initialize_organization(name, manage_roles_permission)` | Anyone | Caller becomes `super_admin`; `manage_roles_permission` is the permission index that allows assign/revoke roles |
| `begin_update` | super_admin | Idle → Updating |
| `commit_update` | super_admin | Updating → Recomputing, bumps version |
| `finish_update` | super_admin | Recomputing → Idle |
| `transfer_super_admin` | super_admin | Transfers super_admin to another signer (new admin must sign). Org PDA address unchanged (uses `original_admin`). |

### Permissions (Updating state)

| Instruction | Auth |
|-------------|------|
| `create_permission(name, description)` | super_admin |
| `delete_permission(perm_index)` | super_admin |

### Roles (Updating state)

| Instruction | Auth |
|-------------|------|
| `create_role(name, description)` | super_admin |
| `delete_role(role_index)` | super_admin |
| `add_role_permission(role_index, permission_index)` | super_admin |
| `remove_role_permission(role_index, permission_index)` | super_admin |
| `add_child_role(parent_index, child_index)` | super_admin |
| `remove_child_role(parent_index, child_index)` | super_admin |
| `recompute_role(role_index, perm_chunk_count)` | super_admin |

> `add_child_role` enforces `parent_index > child_index`, guaranteeing a DAG with no cycles. Recompute children before parents (lowest topo_index first).

### Users (Idle state)

| Instruction | Auth |
|-------------|------|
| `create_user_account` | super_admin |
| `assign_role(role_index, perm_chunk_count)` | super_admin or holder of org’s `manage_roles_permission` |
| `revoke_role(role_index, perm_chunk_count)` | super_admin or holder of org’s `manage_roles_permission` |
| `assign_user_permission(permission_index)` | super_admin |
| `revoke_user_permission(permission_index, perm_chunk_count)` | super_admin |

### Batch & Verification

| Instruction | State | Notes |
|-------------|-------|-------|
| `process_recompute_batch(user_chunk_counts, perm_chunk_count)` | Recomputing | Refreshes multiple user caches in one TX via `remaining_accounts` |
| `has_permission(permission_index)` | Any | O(1) bitmask check on `UserPermCache`; emits `AccessVerified`; usable via CPI |
| `has_role(role_index)` | Any | O(1) bitmask check on `UserPermCache.effective_roles`; usable via CPI |

### Demo Resources

| Instruction | Notes |
|-------------|-------|
| `create_resource(title, resource_id, required_permission)` | Checks caller's `UserPermCache`; stores `required_permission` on resource |
| `delete_resource` | Caller must have the permission stored on the resource; closes `Resource` PDA, refunds rent to creator |

---

## Permission Bitmask

Permissions are stored as a compact byte array — bit `N` set means permission index `N` is granted.

```
Byte 0 = indices 0–7
Byte 1 = indices 8–15
...
Byte k, bit b = index k*8 + b
```

**Manage-roles permission:** Set per-org at `initialize_organization(name, manage_roles_permission)`. Holders of that index can assign/revoke roles (delegation). Convention is often index `3` (`MANAGE_ROLES`).

**Maximum:** 256 permissions per organisation (32-byte fixed cache).

Bitmask helpers (`set_bit`, `clear_bit`, `has_bit`, `bitmask_union`) are in `state.rs` and mirrored in `admin/src/lib/bitmask.ts`.

---

## Permission Check — Three Ways

| Method | Cost | Use case |
|--------|------|----------|
| Read `UserAccount.effective_permissions` off-chain | Free (1 RPC call) | Backend middleware, indexers |
| Simulate `has_permission` transaction | Free | Frontend gating |
| CPI `has_permission` from another program | ~5000 lamports | Atomic on-chain enforcement |

The bitmask is always up-to-date: `assign_role` and `revoke_role` perform inline recompute; `process_recompute_batch` handles the post-commit sweep.

---

## Admin Panel

A browser-based admin UI lives in `admin/`. Connect Phantom or Solflare to manage any organisation without a terminal.

```bash
cd admin
npm install
npm run dev          # http://localhost:5173
```

Environment variables (`.env` or shell):

```
VITE_RPC_URL=http://localhost:8899   # default: localnet
VITE_CLUSTER=localnet                # localnet | devnet | mainnet-beta
```

Tabs: **Overview** (org info + state machine controls) · **Permissions** · **Roles** · **Users**

---

## Development

### Prerequisites

- [Rust](https://rustup.rs/) 1.79+
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) 1.18+
- [Anchor CLI](https://www.anchor-lang.com/docs/installation) 0.32.0
- Node.js 18+

### Build & Test

```bash
# Build the program and regenerate IDL
anchor build

# Run integration tests against a local validator
anchor test

# Start a local validator (separate terminal if running manually)
solana-test-validator
```

### Deploy

```bash
# Localnet
anchor deploy

# Devnet
anchor deploy --provider.cluster devnet
```

---

## CPI Integration

```rust
use anchor_lang::prelude::*;

// Verify a user has permission index 1 before executing protected logic
pub fn my_instruction(ctx: Context<MyCtx>) -> Result<()> {
    let cpi_program = ctx.accounts.rbac_program.to_account_info();
    let cpi_accounts = rbac::cpi::accounts::HasPermission {
        organization: ctx.accounts.organization.to_account_info(),
        user: ctx.accounts.user.to_account_info(),
        user_perm_cache: ctx.accounts.user_perm_cache.to_account_info(),
    };
    rbac::cpi::has_permission(
        CpiContext::new(cpi_program, cpi_accounts),
        1, // permission_index
    )?;
    // If we reach here, the user is authorized
    Ok(())
}
```

If the user lacks the permission or their cache is stale, the CPI returns an error and the entire transaction reverts atomically.

---

## Documentation

| Doc | Description |
|-----|-------------|
| **[Architecture](docs/architecture.md)** | Mermaid diagrams: account model, state machine, instruction flows, auth matrix, CPI integration. |
| **[Security](SECURITY.md)** | Supported versions and how to report vulnerabilities. |

---

## Limits

| Resource | Limit |
|----------|-------|
| Org name length | 32 bytes |
| Role name / permission name | 32 bytes |
| Role / permission description | 128 bytes |
| Roles per chunk | 16 |
| Permissions per chunk | 32 |
| Max permissions per org | 256 (bitmask) |
| Max roles per org (effective cache) | 256 (bitmask) |
| Resource title | 64 bytes |

---

## License

[MIT](LICENSE)
