import { PublicKey } from "@solana/web3.js";
import { PROGRAM_ID, ROLES_PER_CHUNK, PERMS_PER_CHUNK } from "./constants";

export function findOrgPda(name: string): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("organization"), Buffer.from(name)],
    PROGRAM_ID
  );
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

export function roleChunkIndex(roleIndex: number): number {
  return Math.floor(roleIndex / ROLES_PER_CHUNK);
}

export function permChunkIndex(permIndex: number): number {
  return Math.floor(permIndex / PERMS_PER_CHUNK);
}
