import { AnchorProvider, Program, BN } from "@coral-xyz/anchor";
import {
  Connection,
  PublicKey,
  SystemProgram,
  AccountMeta,
} from "@solana/web3.js";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import idl from "@idl";
import type { OrgData, RoleEntry, PermEntry, UserAccountData } from "../types";
import {
  findOrgPda,
  findRoleChunkPda,
  findPermChunkPda,
  findUserAccountPda,
  findUserPermCachePda,
  roleChunkIndex,
  permChunkIndex,
} from "./pda";
import { ROLES_PER_CHUNK, PERMS_PER_CHUNK } from "./constants";
import { bitmaskToIndices } from "./bitmask";

// ---------------------------------------------------------------------------
// Wallet adapter → Anchor wallet bridge
// ---------------------------------------------------------------------------

function makeAnchorWallet(wallet: WalletContextState) {
  if (!wallet.publicKey) throw new Error("Wallet not connected");
  return {
    publicKey: wallet.publicKey,
    signTransaction: wallet.signTransaction!,
    signAllTransactions: wallet.signAllTransactions!,
  };
}

// ---------------------------------------------------------------------------
// Program factory
// ---------------------------------------------------------------------------

export function getProgram(
  connection: Connection,
  wallet: WalletContextState
): Program {
  const anchorWallet = makeAnchorWallet(wallet);
  const provider = new AnchorProvider(connection, anchorWallet as any, {
    commitment: "confirmed",
  });
  return new Program(idl as any, provider);
}

// ---------------------------------------------------------------------------
// OrgState helper
// ---------------------------------------------------------------------------

function parseOrgState(raw: any): "idle" | "updating" | "recomputing" {
  if (raw && typeof raw === "object") {
    if ("idle" in raw) return "idle";
    if ("updating" in raw) return "updating";
    if ("recomputing" in raw) return "recomputing";
  }
  return "idle";
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

export async function fetchOrg(
  program: Program,
  orgName: string
): Promise<OrgData> {
  const [orgPda] = findOrgPda(orgName);
  const raw = await (program.account as any).organization.fetch(orgPda);
  return {
    superAdmin: raw.superAdmin as PublicKey,
    name: raw.name as string,
    memberCount: BigInt(raw.memberCount.toString()),
    nextPermissionIndex: raw.nextPermissionIndex as number,
    roleCount: raw.roleCount as number,
    permissionsVersion: BigInt(raw.permissionsVersion.toString()),
    state: parseOrgState(raw.state),
    bump: raw.bump as number,
  };
}

export async function fetchAllRoles(
  program: Program,
  orgPda: PublicKey,
  roleCount: number
): Promise<RoleEntry[]> {
  const numChunks = Math.ceil(roleCount / ROLES_PER_CHUNK);
  const roles: RoleEntry[] = [];

  for (let ci = 0; ci < numChunks; ci++) {
    const [chunkPda] = findRoleChunkPda(orgPda, ci);
    try {
      const chunk = await (program.account as any).roleChunk.fetch(chunkPda);
      for (const e of chunk.entries) {
        roles.push({
          topoIndex: e.topoIndex as number,
          version: BigInt((e.version as BN).toString()),
          name: e.name as string,
          description: e.description as string,
          directPermissions: Uint8Array.from(e.directPermissions as number[]),
          effectivePermissions: Uint8Array.from(
            e.effectivePermissions as number[]
          ),
          children: e.children as number[],
          active: e.active as boolean,
        });
      }
    } catch {
      // chunk doesn't exist yet — skip
    }
  }

  return roles;
}

export async function fetchAllPerms(
  program: Program,
  orgPda: PublicKey,
  nextPermIndex: number
): Promise<PermEntry[]> {
  const numChunks = Math.ceil(nextPermIndex / PERMS_PER_CHUNK) || 0;
  const perms: PermEntry[] = [];

  for (let ci = 0; ci < numChunks; ci++) {
    const [chunkPda] = findPermChunkPda(orgPda, ci);
    try {
      const chunk = await (program.account as any).permChunk.fetch(chunkPda);
      for (const e of chunk.entries) {
        perms.push({
          index: e.index as number,
          name: e.name as string,
          description: e.description as string,
          createdBy: e.createdBy as PublicKey,
          active: e.active as boolean,
        });
      }
    } catch {
      // chunk doesn't exist yet — skip
    }
  }

  return perms;
}

// ---------------------------------------------------------------------------
// Instruction helpers
// ---------------------------------------------------------------------------

export async function txInitializeOrg(
  program: Program,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  return (program.methods as any)
    .initializeOrganization(orgName)
    .accounts({
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txBeginUpdate(
  program: Program,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  return (program.methods as any)
    .beginUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txCommitUpdate(
  program: Program,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  return (program.methods as any)
    .commitUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txFinishUpdate(
  program: Program,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  return (program.methods as any)
    .finishUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txCreatePermission(
  program: Program,
  orgName: string,
  nextPermIndex: number,
  authority: PublicKey,
  name: string,
  description: string
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = permChunkIndex(nextPermIndex);
  const [permChunkPda] = findPermChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .createPermission(name, description)
    .accounts({
      permChunk: permChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txDeletePermission(
  program: Program,
  orgName: string,
  permIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = permChunkIndex(permIndex);
  const [permChunkPda] = findPermChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .deletePermission(permIndex)
    .accounts({
      permChunk: permChunkPda,
      organization: orgPda,
      authority,
    })
    .rpc();
}

export async function txCreateRole(
  program: Program,
  orgName: string,
  roleCount: number,
  authority: PublicKey,
  name: string,
  description: string
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(roleCount);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .createRole(name, description)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txDeleteRole(
  program: Program,
  orgName: string,
  roleIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(roleIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .deleteRole(roleIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
    })
    .rpc();
}

export async function txAddRolePermission(
  program: Program,
  orgName: string,
  roleIndex: number,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(roleIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .addRolePermission(roleIndex, permissionIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRemoveRolePermission(
  program: Program,
  orgName: string,
  roleIndex: number,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(roleIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .removeRolePermission(roleIndex, permissionIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
    })
    .rpc();
}

export async function txAddChildRole(
  program: Program,
  orgName: string,
  parentIndex: number,
  childIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(parentIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .addChildRole(parentIndex, childIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRemoveChildRole(
  program: Program,
  orgName: string,
  parentIndex: number,
  childIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const chunkIdx = roleChunkIndex(parentIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  return (program.methods as any)
    .removeChildRole(parentIndex, childIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
    })
    .rpc();
}

export async function txRecomputeRole(
  program: Program,
  orgName: string,
  roleIndex: number,
  children: number[],
  directPermissions: Uint8Array,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const myChunkIdx = roleChunkIndex(roleIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, myChunkIdx);

  // Perm chunks for active-permission filtering (first in remaining_accounts)
  const uniquePermChunkIndices = new Set(
    bitmaskToIndices(directPermissions).map(permChunkIndex)
  );
  const permChunkAccounts: AccountMeta[] = [];
  for (const ci of uniquePermChunkIndices) {
    const [pda] = findPermChunkPda(orgPda, ci);
    permChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  // Role chunks for cross-chunk children (after perm chunks)
  const foreignRoleChunkIndices = new Set<number>();
  for (const child of children) {
    const ci = roleChunkIndex(child);
    if (ci !== myChunkIdx) foreignRoleChunkIndices.add(ci);
  }
  const roleChunkAccounts: AccountMeta[] = [];
  for (const ci of foreignRoleChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    roleChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  const remainingAccounts: AccountMeta[] = [...permChunkAccounts, ...roleChunkAccounts];

  return (program.methods as any)
    .recomputeRole(roleIndex, permChunkAccounts.length)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

// ---------------------------------------------------------------------------
// Batch recompute helpers
// ---------------------------------------------------------------------------

/** Fetch all UserAccount PDAs belonging to this org (client-side filter). */
export async function fetchAllUserAccounts(
  program: Program,
  orgPda: PublicKey
): Promise<UserAccountData[]> {
  const all = await (program.account as any).userAccount.all();
  return all
    .filter((a: any) => (a.account.organization as PublicKey).toBase58() === orgPda.toBase58())
    .map((a: any) => ({
      organization: a.account.organization as PublicKey,
      user: a.account.user as PublicKey,
      assignedRoles: (a.account.assignedRoles as any[]).map((r: any) => ({
        topoIndex: r.topoIndex as number,
        lastSeenVersion: BigInt((r.lastSeenVersion as BN).toString()),
      })),
      directPermissions: Uint8Array.from(a.account.directPermissions as number[]),
      effectivePermissions: Uint8Array.from(a.account.effectivePermissions as number[]),
      cachedVersion: BigInt((a.account.cachedVersion as BN).toString()),
      bump: a.account.bump as number,
    }));
}

/**
 * Call processRecomputeBatch for a single user.
 * Requires Recomputing state.
 *
 * Perm chunks are collected from BOTH the user's direct_permissions AND every
 * assigned role's effective_permissions. The on-chain handler then filters each
 * bit through the PermChunk active flag, so deleted permissions are always
 * stripped regardless of whether roles were recomputed in this cycle.
 */
export async function txProcessRecomputeUser(
  program: Program,
  orgName: string,
  user: UserAccountData,
  allRoles: RoleEntry[],
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, user.user);
  const [userPermCachePda] = findUserPermCachePda(orgPda, user.user);

  // Collect every permission index that may appear in this user's result:
  // their own direct_permissions + each assigned role's effective_permissions.
  // The union of perm chunk indices covers everything the on-chain filter will touch.
  const allPermIndices = new Set<number>();
  bitmaskToIndices(user.directPermissions).forEach((i) => allPermIndices.add(i));
  for (const roleRef of user.assignedRoles) {
    const role = allRoles.find((r) => r.topoIndex === roleRef.topoIndex);
    if (role && role.active) {
      bitmaskToIndices(role.effectivePermissions).forEach((i) => allPermIndices.add(i));
    }
  }

  const uniquePermChunkIndices = new Set([...allPermIndices].map(permChunkIndex));
  const permChunkAccounts: AccountMeta[] = [];
  for (const ci of uniquePermChunkIndices) {
    const [pda] = findPermChunkPda(orgPda, ci);
    permChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  // Role chunks for this user's assigned roles (after perm chunks).
  const uniqueRoleChunkIndices = new Set(
    user.assignedRoles.map((r) => roleChunkIndex(r.topoIndex))
  );
  const roleChunkAccounts: AccountMeta[] = [];
  for (const ci of uniqueRoleChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    roleChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  // Layout: [perm_chunks...] [UA, UPC, role_chunks...]
  const remainingAccounts: AccountMeta[] = [
    ...permChunkAccounts,
    { pubkey: userAccountPda, isSigner: false, isWritable: true },
    { pubkey: userPermCachePda, isSigner: false, isWritable: true },
    ...roleChunkAccounts,
  ];

  const userChunkCounts = Buffer.from([uniqueRoleChunkIndices.size]);

  return (program.methods as any)
    .processRecomputeBatch(userChunkCounts, permChunkAccounts.length)
    .accounts({
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

// ---------------------------------------------------------------------------
// User account helpers
// ---------------------------------------------------------------------------

export async function fetchUserAccount(
  program: Program,
  orgPda: PublicKey,
  userKey: PublicKey
): Promise<UserAccountData | null> {
  const [uaPda] = findUserAccountPda(orgPda, userKey);
  try {
    const raw = await (program.account as any).userAccount.fetch(uaPda);
    return {
      organization: raw.organization as PublicKey,
      user: raw.user as PublicKey,
      assignedRoles: (raw.assignedRoles as any[]).map((r) => ({
        topoIndex: r.topoIndex as number,
        lastSeenVersion: BigInt((r.lastSeenVersion as BN).toString()),
      })),
      directPermissions: Uint8Array.from(raw.directPermissions as number[]),
      effectivePermissions: Uint8Array.from(raw.effectivePermissions as number[]),
      cachedVersion: BigInt((raw.cachedVersion as BN).toString()),
      bump: raw.bump as number,
    };
  } catch {
    return null;
  }
}

export async function txCreateUserAccount(
  program: Program,
  orgName: string,
  userKey: PublicKey,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  return (program.methods as any)
    .createUserAccount()
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      user: userKey,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txAssignRole(
  program: Program,
  orgName: string,
  userKey: PublicKey,
  roleIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));
  return (program.methods as any)
    .assignRole(roleIndex)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRevokeRole(
  program: Program,
  orgName: string,
  userKey: PublicKey,
  roleIndex: number,
  remainingRoleIndices: number[], // all roles the user will still have after revoke
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);

  // Unique chunks for all remaining roles
  const uniqueChunkIndices = new Set(remainingRoleIndices.map(roleChunkIndex));
  const remainingAccounts: AccountMeta[] = [];
  for (const ci of uniqueChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    remainingAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  return (program.methods as any)
    .revokeRole(roleIndex)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

export async function txAssignUserPermission(
  program: Program,
  orgName: string,
  userKey: PublicKey,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  return (program.methods as any)
    .assignUserPermission(permissionIndex)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRevokeUserPermission(
  program: Program,
  orgName: string,
  userKey: PublicKey,
  permissionIndex: number,
  assignedRoleIndices: number[], // all roles the user has (for recompute)
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);

  // Unique chunks for all assigned roles (program needs them to recompute)
  const uniqueChunkIndices = new Set(assignedRoleIndices.map(roleChunkIndex));
  const remainingAccounts: AccountMeta[] = [];
  for (const ci of uniqueChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    remainingAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  return (program.methods as any)
    .revokeUserPermission(permissionIndex)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      authority,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}
