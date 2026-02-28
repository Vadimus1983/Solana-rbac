#!/usr/bin/env node

import { Command } from "commander";
import * as anchor from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import {
  getProvider,
  getProgram,
  findOrgPda,
  findRoleChunkPda,
  findPermChunkPda,
  findUserAccountPda,
  findUserPermCachePda,
  findResourcePda,
  explorerUrl,
  hasBit,
  bitmaskToIndices,
  checkPermissionOffchain,
  checkRoleOffchain,
  fetchUserPermCache,
  fetchRoleEntry,
  fetchPermEntry,
  roleChunkIndex,
  roleSlotInChunk,
  permChunkIndex,
  ROLES_PER_CHUNK,
  PERMS_PER_CHUNK,
} from "./utils";

const cli = new Command();

cli
  .name("rbac-cli")
  .description("CLI for the Solana RBAC on-chain program (chunk storage)")
  .version("0.3.0")
  .option("-c, --cluster <cluster>", "Solana cluster", "devnet")
  .option("-k, --keypair <path>", "Path to wallet keypair JSON");

// ═══════════════════════════════════════════════════════════════════════════
// Organization
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("init-org")
  .description("Create a new organization (caller becomes super_admin)")
  .argument("<name>", "Organization name (max 32 chars)")
  .action(async (name: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(name);

    const sig = await program.methods
      .initializeOrganization(name)
      .accounts({ organization: orgPda, authority: provider.wallet.publicKey, systemProgram: SystemProgram.programId })
      .rpc();

    console.log(`Organization "${name}" created.`);
    console.log(`  PDA: ${orgPda.toBase58()}`);
    console.log(`  TX:  ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// State machine
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("begin-update")
  .description("Lock org for editing (Idle → Updating)")
  .argument("<org-name>", "Organization name")
  .action(async (orgName: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);

    const sig = await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: provider.wallet.publicKey })
      .rpc();

    console.log(`Organization "${orgName}" is now in Updating state.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("commit-update")
  .description("Commit edits, bump version (Updating → Recomputing)")
  .argument("<org-name>", "Organization name")
  .action(async (orgName: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);

    const sig = await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: provider.wallet.publicKey })
      .rpc();

    console.log(`Organization "${orgName}" committed, now in Recomputing state.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("finish-update")
  .description("Finish recompute (Recomputing → Idle)")
  .argument("<org-name>", "Organization name")
  .action(async (orgName: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);

    const sig = await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: provider.wallet.publicKey })
      .rpc();

    console.log(`Organization "${orgName}" is now Idle.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// Permissions
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("create-permission")
  .description("Create a new permission (requires Updating state)")
  .argument("<org-name>", "Organization name")
  .argument("<perm-name>", "Permission name (max 32 chars)")
  .argument("[description]", "Permission description", "")
  .action(async (orgName: string, permName: string, description: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const org = await (program.account as any).organization.fetch(orgPda);
    const permIndex: number = org.nextPermissionIndex;
    const chunkIdx = permChunkIndex(permIndex);
    const [permChunkPda] = findPermChunkPda(orgPda, chunkIdx);

    const sig = await program.methods
      .createPermission(permName, description)
      .accounts({
        permChunk: permChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Permission "${permName}" created at index ${permIndex}.`);
    console.log(`  Chunk PDA: ${permChunkPda.toBase58()}`);
    console.log(`  TX:        ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("delete-permission")
  .description("Soft-delete a permission (marks inactive)")
  .argument("<org-name>", "Organization name")
  .argument("<perm-index>", "Permission index")
  .action(async (orgName: string, permIdxStr: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const permIndex = parseInt(permIdxStr);
    const [permChunkPda] = findPermChunkPda(orgPda, permChunkIndex(permIndex));

    const sig = await program.methods
      .deletePermission(permIndex)
      .accounts({
        permChunk: permChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log(`Permission index ${permIndex} soft-deleted.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// Roles
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("create-role")
  .description("Create a new role (requires Updating state)")
  .argument("<org-name>", "Organization name")
  .argument("<role-name>", "Role name (max 32 chars)")
  .argument("[description]", "Role description", "")
  .action(async (orgName: string, roleName: string, description: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const org = await (program.account as any).organization.fetch(orgPda);
    const roleIndex: number = org.roleCount;
    const chunkIdx = roleChunkIndex(roleIndex);
    const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);

    const sig = await program.methods
      .createRole(roleName, description)
      .accounts({
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Role "${roleName}" created at index ${roleIndex}.`);
    console.log(`  Chunk PDA: ${roleChunkPda.toBase58()}`);
    console.log(`  TX:        ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("delete-role")
  .description("Soft-delete a role (sets active=false, clears permissions)")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .action(async (orgName: string, roleIdxStr: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));

    const sig = await program.methods
      .deleteRole(roleIndex)
      .accounts({
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log(`Role index ${roleIndex} soft-deleted.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("add-role-permission")
  .description("Add a permission to a role's direct_permissions bitmask")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .argument("<perm-index>", "Permission index (u32)")
  .action(async (orgName: string, roleIdxStr: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));

    const sig = await program.methods
      .addRolePermission(roleIndex, parseInt(permIdx))
      .accounts({
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Permission index ${permIdx} added to role index ${roleIdxStr}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("remove-role-permission")
  .description("Remove a permission from a role's direct_permissions bitmask")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .argument("<perm-index>", "Permission index (u32)")
  .action(async (orgName: string, roleIdxStr: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));

    const sig = await program.methods
      .removeRolePermission(roleIndex, parseInt(permIdx))
      .accounts({
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log(`Permission index ${permIdx} removed from role index ${roleIdxStr}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("add-child-role")
  .description("Add a child role to a parent role (DAG edge)")
  .argument("<org-name>", "Organization name")
  .argument("<parent-index>", "Parent role index")
  .argument("<child-index>", "Child role index")
  .action(async (orgName: string, parentIdxStr: string, childIdxStr: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const parentIndex = parseInt(parentIdxStr);
    const childIndex = parseInt(childIdxStr);
    const parentChunkIdx = roleChunkIndex(parentIndex);
    const childChunkIdx = roleChunkIndex(childIndex);
    const [parentChunkPda] = findRoleChunkPda(orgPda, parentChunkIdx);

    const remainingAccounts: any[] = [];
    if (childChunkIdx !== parentChunkIdx) {
      const [childChunkPda] = findRoleChunkPda(orgPda, childChunkIdx);
      remainingAccounts.push({ pubkey: childChunkPda, isWritable: false, isSigner: false });
    }

    const sig = await program.methods
      .addChildRole(parentIndex, childIndex)
      .accounts({
        roleChunk: parentChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .rpc();

    console.log(`Child role index ${childIdxStr} added to parent index ${parentIdxStr}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("remove-child-role")
  .description("Remove a child role from a parent role")
  .argument("<org-name>", "Organization name")
  .argument("<parent-index>", "Parent role index")
  .argument("<child-index>", "Child role index")
  .action(async (orgName: string, parentIdxStr: string, childIdxStr: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const parentIndex = parseInt(parentIdxStr);
    const childIndex = parseInt(childIdxStr);
    const [parentChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(parentIndex));

    const sig = await program.methods
      .removeChildRole(parentIndex, childIndex)
      .accounts({
        roleChunk: parentChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log(`Child role index ${childIdxStr} removed from parent index ${parentIdxStr}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("recompute-role")
  .description("Recompute a role's effective_permissions from children")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .argument("[child-indices...]", "Child role indices (space-separated)")
  .action(async (orgName: string, roleIdxStr: string, childIdxStrs: string[]) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const parentChunkIdx = roleChunkIndex(roleIndex);
    const [roleChunkPda] = findRoleChunkPda(orgPda, parentChunkIdx);

    // Deduplicate child chunks, excluding the parent's own chunk.
    const childChunkIdxSet = new Set<number>();
    for (const ci of childIdxStrs || []) {
      const childChunkIdx = roleChunkIndex(parseInt(ci));
      if (childChunkIdx !== parentChunkIdx) {
        childChunkIdxSet.add(childChunkIdx);
      }
    }
    const remainingAccounts = Array.from(childChunkIdxSet).map((chunkIdx) => {
      const [chunkPda] = findRoleChunkPda(orgPda, chunkIdx);
      return { pubkey: chunkPda, isWritable: false, isSigner: false };
    });

    const sig = await program.methods
      .recomputeRole(roleIndex)
      .accounts({
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .rpc();

    console.log(`Role index ${roleIdxStr} effective_permissions recomputed.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// Users
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("create-user-account")
  .description("Create a UserAccount PDA for a user (requires Idle)")
  .argument("<org-name>", "Organization name")
  .argument("<user-pubkey>", "User's wallet public key")
  .action(async (orgName: string, userPubkey: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);
    const [upcPda] = findUserPermCachePda(orgPda, userKey);

    const sig = await program.methods
      .createUserAccount()
      .accounts({
        userAccount: uaPda,
        userPermCache: upcPda,
        organization: orgPda,
        user: userKey,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`UserAccount created for ${userKey.toBase58()}.`);
    console.log(`  UA PDA:  ${uaPda.toBase58()}`);
    console.log(`  UPC PDA: ${upcPda.toBase58()}`);
    console.log(`  TX:      ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("assign-role")
  .description("Assign a role to a user (works in Idle state — immediate effect)")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index to assign")
  .argument("<user-pubkey>", "User's wallet public key")
  .action(async (orgName: string, roleIdxStr: string, userPubkey: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);
    const [upcPda] = findUserPermCachePda(orgPda, userKey);

    const sig = await program.methods
      .assignRole(roleIndex)
      .accounts({
        userAccount: uaPda,
        userPermCache: upcPda,
        roleChunk: roleChunkPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Role index ${roleIdxStr} assigned to ${userKey.toBase58()}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("revoke-role")
  .description("Revoke a role from a user (works in Idle state — immediate effect)")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index to revoke")
  .argument("<user-pubkey>", "User's wallet public key")
  .action(async (orgName: string, roleIdxStr: string, userPubkey: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);
    const [upcPda] = findUserPermCachePda(orgPda, userKey);
    const roleIndex = parseInt(roleIdxStr);

    // Fetch user account to determine remaining role chunks.
    const ua = await (program.account as any).userAccount.fetch(uaPda);
    const remainingRoles: { topoIndex: number }[] = ua.assignedRoles.filter(
      (r: { topoIndex: number }) => r.topoIndex !== roleIndex
    );

    // Deduplicate chunks for remaining roles.
    const chunkIdxSet = new Set<number>(
      remainingRoles.map((r) => roleChunkIndex(r.topoIndex))
    );
    const remainingAccounts = Array.from(chunkIdxSet).map((chunkIdx) => {
      const [chunkPda] = findRoleChunkPda(orgPda, chunkIdx);
      return { pubkey: chunkPda, isWritable: false, isSigner: false };
    });

    const sig = await program.methods
      .revokeRole(roleIndex)
      .accounts({
        userAccount: uaPda,
        userPermCache: upcPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .rpc();

    console.log(`Role index ${roleIdxStr} revoked from ${userKey.toBase58()}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("assign-user-permission")
  .description("Assign a direct permission to a user (works in Idle state)")
  .argument("<org-name>", "Organization name")
  .argument("<user-pubkey>", "User's wallet public key")
  .argument("<perm-index>", "Permission index (u32)")
  .action(async (orgName: string, userPubkey: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);
    const [upcPda] = findUserPermCachePda(orgPda, userKey);

    const sig = await program.methods
      .assignUserPermission(parseInt(permIdx))
      .accounts({
        userAccount: uaPda,
        userPermCache: upcPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Permission index ${permIdx} assigned to ${userKey.toBase58()}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("revoke-user-permission")
  .description("Revoke a direct permission from a user (works in Idle state)")
  .argument("<org-name>", "Organization name")
  .argument("<user-pubkey>", "User's wallet public key")
  .argument("<perm-index>", "Permission index (u32)")
  .action(async (orgName: string, userPubkey: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);
    const [upcPda] = findUserPermCachePda(orgPda, userKey);

    // Fetch user account to find role chunks for recompute.
    const ua = await (program.account as any).userAccount.fetch(uaPda);
    const chunkIdxSet = new Set<number>(
      (ua.assignedRoles as { topoIndex: number }[]).map((r) => roleChunkIndex(r.topoIndex))
    );
    const remainingAccounts = Array.from(chunkIdxSet).map((chunkIdx) => {
      const [chunkPda] = findRoleChunkPda(orgPda, chunkIdx);
      return { pubkey: chunkPda, isWritable: false, isSigner: false };
    });

    const sig = await program.methods
      .revokeUserPermission(parseInt(permIdx))
      .accounts({
        userAccount: uaPda,
        userPermCache: upcPda,
        organization: orgPda,
        authority: provider.wallet.publicKey,
      })
      .remainingAccounts(remainingAccounts)
      .rpc();

    console.log(`Permission index ${permIdx} revoked from ${userKey.toBase58()}.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// Batch recompute (for structural changes only)
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("recompute-users")
  .description("Batch recompute effective_permissions after structural changes (requires Recomputing state)")
  .argument("<org-name>", "Organization name")
  .action(async (orgName: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);

    const org = await (program.account as any).organization.fetch(orgPda);
    console.log(`Fetching all UserAccounts for org "${orgName}"...`);

    const allUAs = await program.account.userAccount.all([
      { memcmp: { offset: 8, bytes: orgPda.toBase58() } },
    ]);

    const staleUsers = allUAs.filter(
      (ua: any) => ua.account.cachedVersion.toNumber() < org.permissionsVersion.toNumber()
    );

    if (staleUsers.length === 0) {
      console.log("All users are up to date. Nothing to recompute.");
      return;
    }

    console.log(`Found ${staleUsers.length} stale user(s). Recomputing in batches...`);

    const BATCH_SIZE = 5;
    let processed = 0;

    for (let i = 0; i < staleUsers.length; i += BATCH_SIZE) {
      const batch = staleUsers.slice(i, i + BATCH_SIZE);
      const userChunkCounts: number[] = [];
      const remainingAccounts: any[] = [];

      for (const ua of batch) {
        const assignedRoles = ua.account.assignedRoles as { topoIndex: number }[];
        // Deduplicate chunks for this user.
        const chunkIdxSet = new Set<number>(
          assignedRoles.map((r) => roleChunkIndex(r.topoIndex))
        );
        const userChunks = Array.from(chunkIdxSet).map((chunkIdx) => {
          const [chunkPda] = findRoleChunkPda(orgPda, chunkIdx);
          return { pubkey: chunkPda, isWritable: false, isSigner: false };
        });

        // Derive the UserPermCache PDA for this user.
        const [upcPda] = findUserPermCachePda(orgPda, ua.account.user as PublicKey);

        userChunkCounts.push(userChunks.length);
        remainingAccounts.push({ pubkey: ua.publicKey, isWritable: true, isSigner: false });
        remainingAccounts.push({ pubkey: upcPda, isWritable: true, isSigner: false });
        for (const chunkAcc of userChunks) {
          remainingAccounts.push(chunkAcc);
        }
      }

      const sig = await program.methods
        .processRecomputeBatch(Buffer.from(userChunkCounts))
        .accounts({
          organization: orgPda,
          authority: provider.wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remainingAccounts)
        .rpc();

      processed += batch.length;
      console.log(`  Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batch.length} user(s) recomputed. TX: ${sig.slice(0, 16)}...`);
    }

    console.log(`Done! ${processed} user(s) recomputed.`);
  });

// ═══════════════════════════════════════════════════════════════════════════
// Verification (off-chain, free)
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("check-permission")
  .description("Off-chain check: does user have a permission? (free, one RPC read)")
  .argument("<org-name>", "Organization name")
  .argument("<user-pubkey>", "User's wallet public key")
  .argument("<perm-index>", "Permission index to check")
  .action(async (orgName: string, userPubkey: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);

    const has = await checkPermissionOffchain(program, orgPda, userKey, parseInt(permIdx));
    console.log(has
      ? `YES: user ${userKey.toBase58()} has permission index ${permIdx}`
      : `NO: user ${userKey.toBase58()} does NOT have permission index ${permIdx}`
    );
  });

cli
  .command("check-role")
  .description("Off-chain check: does user have a role? (free, one RPC read)")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .argument("<user-pubkey>", "User's wallet public key")
  .action(async (orgName: string, roleIdxStr: string, userPubkey: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);
    const userKey = new PublicKey(userPubkey);

    const cache = await fetchUserPermCache(program, orgPda, userKey);
    if (!cache) {
      console.log(`UserPermCache not found for ${userKey.toBase58()}.`);
      return;
    }
    const has = checkRoleOffchain(cache, roleIndex);
    console.log(has
      ? `YES: user ${userKey.toBase58()} has role index ${roleIdxStr}`
      : `NO: user ${userKey.toBase58()} does NOT have role index ${roleIdxStr}`
    );
  });

// ═══════════════════════════════════════════════════════════════════════════
// Inspect
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("inspect-org")
  .description("View organization details")
  .argument("<name>", "Organization name")
  .action(async (name: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(name);

    try {
      const org = await (program.account as any).organization.fetch(orgPda);
      console.log(`Organization: ${org.name}`);
      console.log(`  PDA:                  ${orgPda.toBase58()}`);
      console.log(`  Super Admin:          ${org.superAdmin.toBase58()}`);
      console.log(`  Members:              ${org.memberCount.toString()}`);
      console.log(`  Permissions created:  ${org.nextPermissionIndex}`);
      console.log(`  Roles created:        ${org.roleCount}`);
      console.log(`  Permissions version:  ${org.permissionsVersion.toString()}`);
      console.log(`  State:                ${JSON.stringify(org.state)}`);
    } catch {
      console.log(`Organization "${name}" not found.`);
    }
  });

cli
  .command("inspect-role")
  .description("View role details (reads from chunk)")
  .argument("<org-name>", "Organization name")
  .argument("<role-index>", "Role index")
  .action(async (orgName: string, roleIdxStr: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const roleIndex = parseInt(roleIdxStr);

    const entry = await fetchRoleEntry(program, orgPda, roleIndex);
    if (!entry) {
      console.log(`Role index ${roleIndex} not found in org "${orgName}".`);
      return;
    }
    const [chunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));
    console.log(`Role: ${entry.name}`);
    console.log(`  Chunk PDA:    ${chunkPda.toBase58()}`);
    console.log(`  Description:  ${entry.description}`);
    console.log(`  Active:       ${entry.active}`);
    console.log(`  Topo index:   ${entry.topoIndex}`);
    console.log(`  Version:      ${entry.version.toString()}`);
    console.log(`  Direct perms: [${bitmaskToIndices(entry.directPermissions).join(", ")}]`);
    console.log(`  Effect perms: [${bitmaskToIndices(entry.effectivePermissions).join(", ")}]`);
    console.log(`  Children:     [${(entry.children as number[]).join(", ")}]`);
  });

cli
  .command("inspect-user")
  .description("View user account details")
  .argument("<org-name>", "Organization name")
  .argument("<user-pubkey>", "User's wallet public key")
  .action(async (orgName: string, userPubkey: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const [orgPda] = findOrgPda(orgName);
    const userKey = new PublicKey(userPubkey);
    const [uaPda] = findUserAccountPda(orgPda, userKey);

    try {
      const ua = await (program.account as any).userAccount.fetch(uaPda);
      console.log(`UserAccount for ${ua.user.toBase58()}`);
      console.log(`  PDA:             ${uaPda.toBase58()}`);
      console.log(`  Assigned roles:  ${ua.assignedRoles.length}`);
      for (const r of ua.assignedRoles as { topoIndex: number; lastSeenVersion: any }[]) {
        console.log(`    - role index ${r.topoIndex}  (last_seen_version=${r.lastSeenVersion.toString()})`);
      }
      console.log(`  Direct perms:    [${bitmaskToIndices(ua.directPermissions).join(", ")}]`);
      console.log(`  Effective perms: [${bitmaskToIndices(ua.effectivePermissions).join(", ")}]`);
      console.log(`  Cached version:  ${ua.cachedVersion.toString()}`);
    } catch {
      console.log(`UserAccount not found for ${userKey.toBase58()}.`);
    }
  });

// ═══════════════════════════════════════════════════════════════════════════
// Demo resources
// ═══════════════════════════════════════════════════════════════════════════

cli
  .command("create-resource")
  .description("Create a protected resource (requires a permission)")
  .argument("<org-name>", "Organization name")
  .argument("<title>", "Resource title (max 64 chars)")
  .argument("<resource-id>", "Numeric resource ID")
  .argument("<perm-index>", "Required permission index")
  .action(async (orgName: string, title: string, resourceIdStr: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const resourceId = new anchor.BN(resourceIdStr);
    const [orgPda] = findOrgPda(orgName);
    const [upcPda] = findUserPermCachePda(orgPda, provider.wallet.publicKey);
    const [resourcePda] = findResourcePda(orgPda, resourceId);

    const sig = await program.methods
      .createResource(title, resourceId, parseInt(permIdx))
      .accounts({
        resource: resourcePda,
        organization: orgPda,
        userPermCache: upcPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`Resource "${title}" (id=${resourceIdStr}) created.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

cli
  .command("delete-resource")
  .description("Delete a resource (requires a permission)")
  .argument("<org-name>", "Organization name")
  .argument("<resource-id>", "Numeric resource ID")
  .argument("<perm-index>", "Required permission index")
  .action(async (orgName: string, resourceIdStr: string, permIdx: string) => {
    const opts = cli.opts();
    const provider = getProvider(opts.cluster, opts.keypair);
    const program = getProgram(provider);
    const resourceId = new anchor.BN(resourceIdStr);
    const [orgPda] = findOrgPda(orgName);
    const [upcPda] = findUserPermCachePda(orgPda, provider.wallet.publicKey);
    const [resourcePda] = findResourcePda(orgPda, resourceId);

    const sig = await program.methods
      .deleteResource(parseInt(permIdx))
      .accounts({
        resource: resourcePda,
        organization: orgPda,
        userPermCache: upcPda,
        authority: provider.wallet.publicKey,
      })
      .rpc();

    console.log(`Resource id=${resourceIdStr} deleted.`);
    console.log(`  TX: ${explorerUrl(sig, opts.cluster)}`);
  });

// ═══════════════════════════════════════════════════════════════════════════

cli.parseAsync(process.argv).catch((err) => {
  console.error("Error:", err.message || err);
  process.exit(1);
});
