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
import { PROGRAM_ID, ROLES_PER_CHUNK, PERMS_PER_CHUNK } from "./constants";
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
// Transaction fee helper
// ---------------------------------------------------------------------------

export async function fetchTxFee(
  connection: Connection,
  sig: string
): Promise<number | undefined> {
  try {
    const tx = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    if (!tx?.meta) return undefined;
    // Total lamports that left the fee payer's wallet:
    // includes signature fee + rent deposits for account creation/reallocation.
    const spent = tx.meta.preBalances[0] - tx.meta.postBalances[0];
    return spent > 0 ? spent : tx.meta.fee;
  } catch {
    return undefined;
  }
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

function toBytes(val: unknown): Uint8Array {
  if (!val) return new Uint8Array(0);
  if (val instanceof Uint8Array) return val;
  if (Buffer.isBuffer(val)) return new Uint8Array(val);
  if (Array.isArray(val)) return Uint8Array.from(val as number[]);
  return new Uint8Array(0);
}

function rawToOrgData(raw: any): OrgData {
  return {
    superAdmin: raw.superAdmin as PublicKey,
    originalAdmin: raw.originalAdmin as PublicKey,
    name: raw.name as string,
    memberCount: BigInt(raw.memberCount.toString()),
    nextPermissionIndex: raw.nextPermissionIndex as number,
    roleCount: raw.roleCount as number,
    permissionsVersion: BigInt(raw.permissionsVersion.toString()),
    state: parseOrgState(raw.state),
    bump: raw.bump as number,
    manageRolesPermission: raw.manageRolesPermission as number,
  };
}

/**
 * Fetch an organization by trying the connected wallet as original_admin first
 * (fast path), then falling back to a getProgramAccounts search by name.
 */
export async function fetchOrg(
  program: Program,
  callerKey: PublicKey,
  orgName: string
): Promise<OrgData> {
  // Fast path: caller is the original admin
  try {
    const [orgPda] = findOrgPda(callerKey, orgName);
    const raw = await (program.account as any).organization.fetch(orgPda);
    return rawToOrgData(raw);
  } catch {
    // Caller is not the original admin — search all org accounts by name
  }

  const all = await (program.account as any).organization.all();
  for (const a of all) {
    if ((a.account.name as string) === orgName) {
      return rawToOrgData(a.account);
    }
  }
  throw new Error("Account does not exist or has no data");
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
          directPermissions: toBytes(e.directPermissions),
          effectivePermissions: toBytes(e.effectivePermissions),
          children: (e.children as number[]) ?? [],
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
  authority: PublicKey,
  manageRolesPermission: number
): Promise<string> {
  const [orgPda] = findOrgPda(authority, orgName);
  return (program.methods as any)
    .initializeOrganization(orgName, manageRolesPermission)
    .accounts({
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txBeginUpdate(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .beginUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txCommitUpdate(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .commitUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txFinishUpdate(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .finishUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

export async function txCreatePermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  nextPermIndex: number,
  authority: PublicKey,
  name: string,
  description: string
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  permIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  roleCount: number,
  authority: PublicKey,
  name: string,
  description: string
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  roleIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  roleIndex: number,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));
  const [permChunkPda] = findPermChunkPda(orgPda, permChunkIndex(permissionIndex));
  return (program.methods as any)
    .addRolePermission(roleIndex, permissionIndex)
    .accounts({
      roleChunk: roleChunkPda,
      permChunk: permChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRemoveRolePermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  roleIndex: number,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  parentIndex: number,
  childIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const parentChunkIdx = roleChunkIndex(parentIndex);
  const childChunkIdx = roleChunkIndex(childIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, parentChunkIdx);

  // If parent and child live in different chunks, the on-chain handler requires
  // the child's RoleChunk in remaining_accounts[0] for cross-chunk validation.
  const remainingAccounts: AccountMeta[] = [];
  if (childChunkIdx !== parentChunkIdx) {
    const [childChunkPda] = findRoleChunkPda(orgPda, childChunkIdx);
    remainingAccounts.push({ pubkey: childChunkPda, isSigner: false, isWritable: false });
  }

  return (program.methods as any)
    .addChildRole(parentIndex, childIndex)
    .accounts({
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

export async function txRemoveChildRole(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  parentIndex: number,
  childIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  roleIndex: number,
  children: number[],
  directPermissions: Uint8Array,
  authority: PublicKey,
  allRoles: RoleEntry[] = [],
  nextPermissionIndex: number = 0
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const myChunkIdx = roleChunkIndex(roleIndex);
  const [roleChunkPda] = findRoleChunkPda(orgPda, myChunkIdx);

  // Collect perm chunk indices from this role's directPermissions AND from
  // each child's effectivePermissions. The on-chain handler filters child bits
  // through perm chunks when perm_chunk_count > 0, so all relevant chunks
  // must be present in remaining_accounts.
  const uniquePermChunkIndices = new Set(
    bitmaskToIndices(directPermissions).map(permChunkIndex)
  );
  for (const childIdx of children) {
    const childRole = allRoles.find((r) => r.topoIndex === childIdx);
    if (childRole && childRole.active) {
      bitmaskToIndices(childRole.effectivePermissions).forEach((pi) =>
        uniquePermChunkIndices.add(permChunkIndex(pi))
      );
    }
  }
  // On-chain check: perm_chunk_count must be > 0 when org has any permissions.
  if (nextPermissionIndex > 0 && uniquePermChunkIndices.size === 0) {
    uniquePermChunkIndices.add(0);
  }

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
      directPermissions: toBytes(a.account.directPermissions),
      effectivePermissions: toBytes(a.account.effectivePermissions),
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
  originalAdmin: PublicKey,
  orgName: string,
  user: UserAccountData,
  allRoles: RoleEntry[],
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
      assignedRoles: (raw.assignedRoles as any[] ?? []).map((r) => ({
        topoIndex: r.topoIndex as number,
        lastSeenVersion: BigInt((r.lastSeenVersion as BN).toString()),
      })),
      directPermissions: toBytes(raw.directPermissions),
      effectivePermissions: toBytes(raw.effectivePermissions),
      cachedVersion: BigInt((raw.cachedVersion as BN).toString()),
      bump: raw.bump as number,
    };
  } catch {
    return null;
  }
}

export async function txCreateUserAccount(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
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
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  roleIndex: number,
  roleEffectivePermissions: Uint8Array,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));

  // Build PermChunk accounts for active-permission filtering.
  // The on-chain handler strips any stale deleted-permission bits from the
  // role's effective_permissions before merging them into the user's cache.
  const uniquePermChunkIndices = new Set(
    bitmaskToIndices(roleEffectivePermissions).map(permChunkIndex)
  );
  const remainingAccounts: AccountMeta[] = [];
  for (const ci of uniquePermChunkIndices) {
    const [pda] = findPermChunkPda(orgPda, ci);
    remainingAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  return (program.methods as any)
    .assignRole(roleIndex, remainingAccounts.length)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

export async function txRevokeRole(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  roleIndex: number,
  remainingRoleIndices: number[],
  directPermissions: Uint8Array,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  const [roleChunkPda] = findRoleChunkPda(orgPda, roleChunkIndex(roleIndex));

  const uniquePermChunkIndices = new Set(
    bitmaskToIndices(directPermissions).map(permChunkIndex)
  );
  const permChunkAccounts: AccountMeta[] = [];
  for (const ci of uniquePermChunkIndices) {
    const [pda] = findPermChunkPda(orgPda, ci);
    permChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  const uniqueRoleChunkIndices = new Set(remainingRoleIndices.map(roleChunkIndex));
  const roleChunkAccounts: AccountMeta[] = [];
  for (const ci of uniqueRoleChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    roleChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  const remainingAccounts: AccountMeta[] = [...permChunkAccounts, ...roleChunkAccounts];

  return (program.methods as any)
    .revokeRole(roleIndex, permChunkAccounts.length)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      roleChunk: roleChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

export async function txAssignUserPermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  permissionIndex: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  const [permChunkPda] = findPermChunkPda(orgPda, permChunkIndex(permissionIndex));
  return (program.methods as any)
    .assignUserPermission(permissionIndex)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      permChunk: permChunkPda,
      organization: orgPda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txRevokeUserPermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  permissionIndex: number,
  assignedRoleIndices: number[],
  directPermissions: Uint8Array,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);

  // Compute remaining direct perm indices after clearing the revoked bit,
  // then build perm chunk accounts for filtering (first in remaining_accounts).
  const afterClear = directPermissions.slice();
  const byteIdx = Math.floor(permissionIndex / 8);
  if (byteIdx < afterClear.length) afterClear[byteIdx] &= ~(1 << (permissionIndex % 8));
  const uniquePermChunkIndices = new Set(
    bitmaskToIndices(afterClear).map(permChunkIndex)
  );
  const permChunkAccounts: AccountMeta[] = [];
  for (const ci of uniquePermChunkIndices) {
    const [pda] = findPermChunkPda(orgPda, ci);
    permChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  // Role chunks for all assigned roles (after perm chunks)
  const uniqueRoleChunkIndices = new Set(assignedRoleIndices.map(roleChunkIndex));
  const roleChunkAccounts: AccountMeta[] = [];
  for (const ci of uniqueRoleChunkIndices) {
    const [pda] = findRoleChunkPda(orgPda, ci);
    roleChunkAccounts.push({ pubkey: pda, isSigner: false, isWritable: false });
  }

  const remainingAccounts: AccountMeta[] = [...permChunkAccounts, ...roleChunkAccounts];

  return (program.methods as any)
    .revokeUserPermission(permissionIndex, permChunkAccounts.length)
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      authority,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}

// ---------------------------------------------------------------------------
// Access verification (read-only on-chain checks)
// ---------------------------------------------------------------------------

/** Calls the on-chain has_permission instruction.
 *  Resolves normally if the user has the permission and the cache is fresh.
 *  Throws AnchorError with code "InsufficientPermission" or "StalePermissions". */
export async function txHasPermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  permissionIndex: number
): Promise<void> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  await (program.methods as any)
    .hasPermission(permissionIndex)
    .accounts({
      organization: orgPda,
      user: userKey,
      userPermCache: userPermCachePda,
    })
    .rpc();
}

/** Calls the on-chain has_role instruction.
 *  Resolves normally if the user has the role and the cache is fresh.
 *  Throws AnchorError with code "RoleNotAssigned" or "StalePermissions". */
export async function txHasRole(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  roleIndex: number
): Promise<void> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  await (program.methods as any)
    .hasRole(roleIndex)
    .accounts({
      organization: orgPda,
      user: userKey,
      userPermCache: userPermCachePda,
    })
    .rpc();
}

// ---------------------------------------------------------------------------
// Cancel update
// ---------------------------------------------------------------------------

export async function txCancelUpdate(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .cancelUpdate()
    .accounts({ organization: orgPda, authority })
    .rpc();
}

// ---------------------------------------------------------------------------
// Close user account
// ---------------------------------------------------------------------------

export async function txCloseUserAccount(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  userKey: PublicKey,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userAccountPda] = findUserAccountPda(orgPda, userKey);
  const [userPermCachePda] = findUserPermCachePda(orgPda, userKey);
  return (program.methods as any)
    .closeUserAccount()
    .accounts({
      userAccount: userAccountPda,
      userPermCache: userPermCachePda,
      organization: orgPda,
      authority,
    })
    .rpc();
}

// ---------------------------------------------------------------------------
// Transfer super admin
// ---------------------------------------------------------------------------

export async function txTransferSuperAdmin(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  newSuperAdmin: PublicKey,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .transferSuperAdmin()
    .accounts({
      organization: orgPda,
      newSuperAdmin,
      authority,
    })
    .rpc();
}

// ---------------------------------------------------------------------------
// Update manage_roles_permission
// ---------------------------------------------------------------------------

export async function txUpdateManageRolesPermission(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  newManageRolesPermission: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  return (program.methods as any)
    .updateManageRolesPermission(newManageRolesPermission)
    .accounts({
      organization: orgPda,
      authority,
    })
    .rpc();
}

// ---------------------------------------------------------------------------
// Demo resources
// ---------------------------------------------------------------------------

function findResourcePda(
  orgKey: PublicKey,
  creatorKey: PublicKey,
  resourceId: bigint
): [PublicKey, number] {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(resourceId, 0);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("resource"), orgKey.toBuffer(), creatorKey.toBuffer(), buf],
    PROGRAM_ID
  );
}

export async function txCreateResource(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  title: string,
  resourceId: bigint,
  requiredPermission: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userPermCachePda] = findUserPermCachePda(orgPda, authority);
  const [resourcePda] = findResourcePda(orgPda, authority, resourceId);
  return (program.methods as any)
    .createResource(title, new BN(resourceId.toString()), requiredPermission)
    .accounts({
      resource: resourcePda,
      organization: orgPda,
      userPermCache: userPermCachePda,
      authority,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
}

export async function txDeleteResource(
  program: Program,
  originalAdmin: PublicKey,
  orgName: string,
  resourceCreator: PublicKey,
  resourceId: bigint,
  requiredPermission: number,
  authority: PublicKey
): Promise<string> {
  const [orgPda] = findOrgPda(originalAdmin, orgName);
  const [userPermCachePda] = findUserPermCachePda(orgPda, authority);
  const [resourcePda] = findResourcePda(orgPda, resourceCreator, resourceId);

  const [permChunkPda] = findPermChunkPda(orgPda, permChunkIndex(requiredPermission));
  const remainingAccounts: AccountMeta[] = [
    { pubkey: permChunkPda, isSigner: false, isWritable: false },
  ];

  return (program.methods as any)
    .deleteResource()
    .accounts({
      resource: resourcePda,
      organization: orgPda,
      userPermCache: userPermCachePda,
      authority,
      resourceCreator,
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
}
