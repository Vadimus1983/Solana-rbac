import { PublicKey } from "@solana/web3.js";

export type OrgStateKind = "idle" | "updating" | "recomputing";

export interface OrgData {
  superAdmin: PublicKey;
  name: string;
  memberCount: bigint;
  nextPermissionIndex: number;
  roleCount: number;
  permissionsVersion: bigint;
  state: OrgStateKind;
  bump: number;
}

export interface RoleEntry {
  topoIndex: number;
  version: bigint;
  name: string;
  description: string;
  directPermissions: Uint8Array;
  effectivePermissions: Uint8Array;
  children: number[];
  active: boolean;
}

export interface PermEntry {
  index: number;
  name: string;
  description: string;
  createdBy: PublicKey;
  active: boolean;
}

export interface UserAccountData {
  organization: PublicKey;
  user: PublicKey;
  assignedRoles: { topoIndex: number; lastSeenVersion: bigint }[];
  directPermissions: Uint8Array;
  effectivePermissions: Uint8Array;
  cachedVersion: bigint;
  bump: number;
}

export interface Toast {
  id: number;
  status: "pending" | "success" | "error";
  message: string;
  txSig?: string;
  cluster?: string;
}
