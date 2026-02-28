import {
  Connection,
  Keypair,
  PublicKey,
  clusterApiUrl,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export const PROGRAM_ID = new PublicKey(
  "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"
);

export const ROLES_PER_CHUNK = 16;
export const PERMS_PER_CHUNK = 32;

// ---------------------------------------------------------------------------
// Bitmask helpers (mirrors on-chain has_bit / set_bit)
// ---------------------------------------------------------------------------

export function hasBit(bitmask: Buffer | Uint8Array | number[], index: number): boolean {
  const bytePos = Math.floor(index / 8);
  const bitPos = index % 8;
  return bytePos < bitmask.length && (bitmask[bytePos] & (1 << bitPos)) !== 0;
}

export function bitmaskToIndices(bitmask: Buffer | Uint8Array | number[]): number[] {
  const indices: number[] = [];
  for (let byteIdx = 0; byteIdx < bitmask.length; byteIdx++) {
    for (let bit = 0; bit < 8; bit++) {
      if (bitmask[byteIdx] & (1 << bit)) {
        indices.push(byteIdx * 8 + bit);
      }
    }
  }
  return indices;
}

// ---------------------------------------------------------------------------
// Connection / provider helpers
// ---------------------------------------------------------------------------

export function getConnection(cluster: string): Connection {
  if (cluster === "localnet" || cluster === "localhost") {
    return new Connection("http://localhost:8899", "confirmed");
  }
  return new Connection(clusterApiUrl(cluster as any), "confirmed");
}

export function loadKeypair(filepath?: string): Keypair {
  const resolved =
    filepath || path.join(os.homedir(), ".config", "solana", "id.json");
  const raw = JSON.parse(fs.readFileSync(resolved, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

export function loadIdl(): any {
  const idlPath = path.resolve(__dirname, "../../target/idl/rbac.json");
  return JSON.parse(fs.readFileSync(idlPath, "utf-8"));
}

export function getProvider(
  cluster: string,
  keypairPath?: string
): anchor.AnchorProvider {
  const connection = getConnection(cluster);
  const wallet = new anchor.Wallet(loadKeypair(keypairPath));
  return new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
}

export function getProgram(provider: anchor.AnchorProvider): anchor.Program {
  const idl = loadIdl();
  return new anchor.Program(idl, provider);
}

// ---------------------------------------------------------------------------
// PDA derivation helpers
// ---------------------------------------------------------------------------

export function findOrgPda(name: string): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("organization"), Buffer.from(name)],
    PROGRAM_ID
  );
}

/** chunk index for a given role index */
export function roleChunkIndex(roleIndex: number): number {
  return Math.floor(roleIndex / ROLES_PER_CHUNK);
}

/** slot within a chunk for a given role index */
export function roleSlotInChunk(roleIndex: number): number {
  return roleIndex % ROLES_PER_CHUNK;
}

/** chunk index for a given permission index */
export function permChunkIndex(permIndex: number): number {
  return Math.floor(permIndex / PERMS_PER_CHUNK);
}

export function findRoleChunkPda(
  orgKey: PublicKey,
  chunkIndex: number
): [PublicKey, number] {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(chunkIndex, 0);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("role_chunk"), orgKey.toBuffer(), buf],
    PROGRAM_ID
  );
}

export function findPermChunkPda(
  orgKey: PublicKey,
  chunkIndex: number
): [PublicKey, number] {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(chunkIndex, 0);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("perm_chunk"), orgKey.toBuffer(), buf],
    PROGRAM_ID
  );
}

export function findUserAccountPda(
  orgKey: PublicKey,
  userKey: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("user_account"),
      orgKey.toBuffer(),
      userKey.toBuffer(),
    ],
    PROGRAM_ID
  );
}

export function findUserPermCachePda(
  orgKey: PublicKey,
  userKey: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("user_perm_cache"),
      orgKey.toBuffer(),
      userKey.toBuffer(),
    ],
    PROGRAM_ID
  );
}

export function findResourcePda(
  orgKey: PublicKey,
  resourceId: anchor.BN
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("resource"),
      orgKey.toBuffer(),
      resourceId.toArrayLike(Buffer, "le", 8),
    ],
    PROGRAM_ID
  );
}

export function explorerUrl(sig: string, cluster: string): string {
  const suffix = cluster === "devnet" ? "?cluster=devnet" : "";
  return `https://explorer.solana.com/tx/${sig}${suffix}`;
}

// ---------------------------------------------------------------------------
// Fetch helpers for chunk-based accounts
// ---------------------------------------------------------------------------

/**
 * Fetch a single RoleEntry from the on-chain RoleChunk.
 * Returns null if the chunk or slot doesn't exist.
 */
export async function fetchRoleEntry(
  program: anchor.Program,
  orgPda: PublicKey,
  roleIndex: number
): Promise<any | null> {
  const chunkIdx = roleChunkIndex(roleIndex);
  const slot = roleSlotInChunk(roleIndex);
  const [chunkPda] = findRoleChunkPda(orgPda, chunkIdx);
  try {
    const chunk = await (program.account as any).roleChunk.fetch(chunkPda);
    if (slot >= chunk.entries.length) return null;
    return chunk.entries[slot];
  } catch {
    return null;
  }
}

/**
 * Fetch a single PermEntry from the on-chain PermChunk.
 * Returns null if the chunk or slot doesn't exist.
 */
export async function fetchPermEntry(
  program: anchor.Program,
  orgPda: PublicKey,
  permIndex: number
): Promise<any | null> {
  const chunkIdx = permChunkIndex(permIndex);
  const slot = permIndex % PERMS_PER_CHUNK;
  const [chunkPda] = findPermChunkPda(orgPda, chunkIdx);
  try {
    const chunk = await (program.account as any).permChunk.fetch(chunkPda);
    if (slot >= chunk.entries.length) return null;
    return chunk.entries[slot];
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Fetch helpers for UserPermCache
// ---------------------------------------------------------------------------

export async function fetchUserPermCache(
  program: anchor.Program,
  orgPda: PublicKey,
  userKey: PublicKey
): Promise<any | null> {
  const [upcPda] = findUserPermCachePda(orgPda, userKey);
  try {
    return await (program.account as any).userPermCache.fetch(upcPda);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Off-chain permission check (free, one RPC call)
// ---------------------------------------------------------------------------

export async function checkPermissionOffchain(
  program: anchor.Program,
  orgPda: PublicKey,
  userKey: PublicKey,
  permissionIndex: number
): Promise<boolean> {
  const cache = await fetchUserPermCache(program, orgPda, userKey);
  if (!cache) return false;
  return hasBit(cache.effectivePermissions, permissionIndex);
}

export function checkRoleOffchain(cache: any, roleIndex: number): boolean {
  return hasBit(cache.effectiveRoles, roleIndex);
}
