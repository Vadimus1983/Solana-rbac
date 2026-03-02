import React, { useState, useCallback } from "react";
import { PublicKey } from "@solana/web3.js";
import type { OrgData, RoleEntry, PermEntry, UserAccountData, Toast } from "../types";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import { Connection } from "@solana/web3.js";
import { bitmaskToIndices } from "../lib/bitmask";
import { findOrgPda } from "../lib/pda";
import {
  getProgram,
  fetchUserAccount,
  txCreateUserAccount,
  txAssignRole,
  txRevokeRole,
  txAssignUserPermission,
  txRevokeUserPermission,
} from "../lib/program";

interface Props {
  orgName: string;
  orgData: OrgData;
  allRoles: RoleEntry[];
  allPerms: PermEntry[];
  wallet: WalletContextState;
  connection: Connection;
  addToast: (t: Omit<Toast, "id">) => number;
  updateToast: (id: number, update: Partial<Toast>) => void;
}

export default function Users({
  orgName,
  orgData,
  allRoles,
  allPerms,
  wallet,
  connection,
  addToast,
  updateToast,
}: Props) {
  const [userInput, setUserInput] = useState("");
  const [userData, setUserData] = useState<UserAccountData | null>(null);
  const [userNotFound, setUserNotFound] = useState(false);
  const [loadingUser, setLoadingUser] = useState(false);
  const [busy, setBusy] = useState(false);
  const [assignRoleIdx, setAssignRoleIdx] = useState<number | "">("");
  const [assignPermIdx, setAssignPermIdx] = useState<number | "">("");

  const isIdle = orgData.state === "idle";
  const isSuperAdmin =
    wallet.publicKey?.toBase58() === orgData.superAdmin.toBase58();
  const canWrite = isIdle && isSuperAdmin && wallet.connected;
  const notIdleMsg = "Organization must be in Idle state";

  const run = useCallback(
    async (label: string, fn: () => Promise<string>) => {
      setBusy(true);
      const id = addToast({ status: "pending", message: `Sending ${label}…` });
      try {
        const sig = await fn();
        updateToast(id, { status: "success", message: `${label} confirmed`, txSig: sig });
        return true;
      } catch (e: any) {
        updateToast(id, { status: "error", message: e?.message ?? `${label} failed` });
        return false;
      } finally {
        setBusy(false);
      }
    },
    [addToast, updateToast]
  );

  const loadUser = useCallback(async (key: string) => {
    const trimmed = key.trim();
    if (!trimmed || !wallet.publicKey) return;

    let userKey: PublicKey;
    try {
      userKey = new PublicKey(trimmed);
    } catch {
      setUserData(null);
      setUserNotFound(false);
      addToast({ status: "error", message: "Invalid public key" });
      return;
    }

    setLoadingUser(true);
    setUserData(null);
    setUserNotFound(false);

    try {
      const program = getProgram(connection, wallet);
      const [orgPda] = findOrgPda(orgName);
      const ua = await fetchUserAccount(program, orgPda, userKey);
      if (ua) {
        setUserData(ua);
      } else {
        setUserNotFound(true);
      }
    } finally {
      setLoadingUser(false);
    }
  }, [wallet, connection, orgName, addToast]);

  const refreshUser = useCallback(async () => {
    if (userInput.trim()) await loadUser(userInput);
  }, [userInput, loadUser]);

  const handleCreateUserAccount = async () => {
    if (!wallet.publicKey) return;
    let userKey: PublicKey;
    try { userKey = new PublicKey(userInput.trim()); } catch { return; }
    const program = getProgram(connection, wallet);
    const ok = await run("Create User Account", () =>
      txCreateUserAccount(program, orgName, userKey, wallet.publicKey!)
    );
    if (ok) await refreshUser();
  };

  const handleAssignRole = async () => {
    if (!userData || assignRoleIdx === "" || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    const ok = await run(`Assign Role #${assignRoleIdx}`, () =>
      txAssignRole(program, orgName, userData.user, assignRoleIdx as number, wallet.publicKey!)
    );
    if (ok) { setAssignRoleIdx(""); await refreshUser(); }
  };

  const handleRevokeRole = async (roleIndex: number) => {
    if (!userData || !wallet.publicKey) return;
    const remainingRoles = userData.assignedRoles
      .map((r) => r.topoIndex)
      .filter((i) => i !== roleIndex);
    const program = getProgram(connection, wallet);
    const ok = await run(`Revoke Role #${roleIndex}`, () =>
      txRevokeRole(program, orgName, userData.user, roleIndex, remainingRoles, wallet.publicKey!)
    );
    if (ok) await refreshUser();
  };

  const handleAssignPerm = async () => {
    if (!userData || assignPermIdx === "" || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    const ok = await run(`Assign Permission #${assignPermIdx}`, () =>
      txAssignUserPermission(program, orgName, userData.user, assignPermIdx as number, wallet.publicKey!)
    );
    if (ok) { setAssignPermIdx(""); await refreshUser(); }
  };

  const handleRevokePerm = async (permIndex: number) => {
    if (!userData || !wallet.publicKey) return;
    const assignedRoleIndices = userData.assignedRoles.map((r) => r.topoIndex);
    const program = getProgram(connection, wallet);
    const ok = await run(`Revoke Permission #${permIndex}`, () =>
      txRevokeUserPermission(program, orgName, userData.user, permIndex, assignedRoleIndices, wallet.publicKey!)
    );
    if (ok) await refreshUser();
  };

  const assignedRoleIndices = userData?.assignedRoles.map((r) => r.topoIndex) ?? [];
  const directPermIndices = userData ? bitmaskToIndices(userData.directPermissions) : [];
  const effectivePermIndices = userData ? bitmaskToIndices(userData.effectivePermissions) : [];

  const availableRoles = allRoles.filter(
    (r) => r.active && !assignedRoleIndices.includes(r.topoIndex)
  );
  const availablePerms = allPerms.filter(
    (p) => p.active && !directPermIndices.includes(p.index)
  );

  return (
    <div className="space-y-6">
      {/* User lookup */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
        <h2 className="text-lg font-semibold text-gray-900 mb-3">Look Up User</h2>
        <div className="flex gap-2 items-center">
          <input
            type="text"
            className="border border-gray-300 rounded px-3 py-1.5 text-sm flex-1 font-mono focus:outline-none focus:ring-2 focus:ring-indigo-300"
            placeholder="User public key (base58)"
            value={userInput}
            onChange={(e) => setUserInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && loadUser(userInput)}
          />
          <button
            onClick={() => loadUser(userInput)}
            disabled={!userInput.trim() || !wallet.connected || loadingUser}
            className="px-4 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            {loadingUser ? "Loading…" : "Load"}
          </button>
          {userData && (
            <button
              onClick={refreshUser}
              disabled={loadingUser || busy}
              className="px-3 py-1.5 bg-gray-200 text-gray-700 text-sm rounded hover:bg-gray-300 disabled:opacity-50"
            >
              Refresh
            </button>
          )}
        </div>

        {userNotFound && (
          <div className="mt-3 flex items-center gap-3 p-3 bg-amber-50 border border-amber-200 rounded-lg text-sm">
            <span className="text-amber-700">
              No account found for this user in org <span className="font-semibold">"{orgName}"</span>.
            </span>
            <button
              onClick={handleCreateUserAccount}
              disabled={!canWrite || busy}
              title={!isIdle ? notIdleMsg : !isSuperAdmin ? "Only super_admin" : undefined}
              className="px-3 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors whitespace-nowrap"
            >
              {busy ? "Creating…" : "Create Account"}
            </button>
          </div>
        )}
      </div>

      {/* User detail panel */}
      {userData && (
        <div className="space-y-4">
          {/* Info card */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
            <h3 className="font-semibold text-gray-900 mb-3">User Account</h3>
            <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
              <div>
                <dt className="text-gray-500">Public Key</dt>
                <dd className="font-mono text-xs text-gray-800 mt-0.5 break-all">
                  {userData.user.toBase58()}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Cached Version</dt>
                <dd className="font-semibold text-gray-800 mt-0.5">
                  {userData.cachedVersion.toString()}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Effective Permissions</dt>
                <dd className="font-mono text-xs text-gray-800 mt-0.5">
                  {effectivePermIndices.length
                    ? effectivePermIndices.map((i) => {
                        const p = allPerms.find((p) => p.index === i);
                        return `${i}${p ? `:${p.name}` : ""}`;
                      }).join(", ")
                    : "—"}
                </dd>
              </div>
            </dl>
          </div>

          {/* Assigned Roles */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
            <h3 className="font-semibold text-gray-900 mb-3">Assigned Roles</h3>
            {assignedRoleIndices.length === 0 ? (
              <p className="text-sm text-gray-400 mb-3">No roles assigned.</p>
            ) : (
              <div className="flex flex-wrap gap-2 mb-3">
                {userData.assignedRoles.map((r) => {
                  const role = allRoles.find((ro) => ro.topoIndex === r.topoIndex);
                  return (
                    <span
                      key={r.topoIndex}
                      className="flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 border border-indigo-200 rounded-full text-sm text-indigo-700"
                    >
                      <span>#{r.topoIndex} {role?.name ?? "unknown"}</span>
                      <button
                        onClick={() => handleRevokeRole(r.topoIndex)}
                        disabled={!canWrite || busy}
                        title={!isIdle ? notIdleMsg : !isSuperAdmin ? "Only super_admin" : "Revoke role"}
                        className="text-indigo-300 hover:text-red-500 disabled:opacity-40 font-bold leading-none"
                      >
                        ×
                      </button>
                    </span>
                  );
                })}
              </div>
            )}
            <div className="flex gap-2">
              <select
                className="flex-1 border border-gray-300 rounded px-2 py-1.5 text-sm disabled:opacity-50"
                value={assignRoleIdx}
                onChange={(e) =>
                  setAssignRoleIdx(e.target.value === "" ? "" : Number(e.target.value))
                }
                disabled={!canWrite || availableRoles.length === 0}
              >
                <option value="">— assign role —</option>
                {availableRoles.map((r) => (
                  <option key={r.topoIndex} value={r.topoIndex}>
                    #{r.topoIndex}: {r.name}
                  </option>
                ))}
              </select>
              <button
                onClick={handleAssignRole}
                disabled={!canWrite || assignRoleIdx === "" || busy}
                title={!isIdle ? notIdleMsg : !isSuperAdmin ? "Only super_admin" : undefined}
                className="px-4 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors"
              >
                Assign
              </button>
            </div>
          </div>

          {/* Direct Permissions */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
            <h3 className="font-semibold text-gray-900 mb-3">Direct Permissions</h3>
            {directPermIndices.length === 0 ? (
              <p className="text-sm text-gray-400 mb-3">No direct permissions.</p>
            ) : (
              <div className="flex flex-wrap gap-2 mb-3">
                {directPermIndices.map((pi) => {
                  const perm = allPerms.find((p) => p.index === pi);
                  return (
                    <span
                      key={pi}
                      className="flex items-center gap-1.5 px-2.5 py-1 bg-green-50 border border-green-200 rounded-full text-sm text-green-700"
                    >
                      <span>#{pi} {perm?.name ?? "unknown"}</span>
                      <button
                        onClick={() => handleRevokePerm(pi)}
                        disabled={!canWrite || busy}
                        title={!isIdle ? notIdleMsg : !isSuperAdmin ? "Only super_admin" : "Revoke permission"}
                        className="text-green-300 hover:text-red-500 disabled:opacity-40 font-bold leading-none"
                      >
                        ×
                      </button>
                    </span>
                  );
                })}
              </div>
            )}
            <div className="flex gap-2">
              <select
                className="flex-1 border border-gray-300 rounded px-2 py-1.5 text-sm disabled:opacity-50"
                value={assignPermIdx}
                onChange={(e) =>
                  setAssignPermIdx(e.target.value === "" ? "" : Number(e.target.value))
                }
                disabled={!canWrite || availablePerms.length === 0}
              >
                <option value="">— assign direct permission —</option>
                {availablePerms.map((p) => (
                  <option key={p.index} value={p.index}>
                    #{p.index}: {p.name}
                  </option>
                ))}
              </select>
              <button
                onClick={handleAssignPerm}
                disabled={!canWrite || assignPermIdx === "" || busy}
                title={!isIdle ? notIdleMsg : !isSuperAdmin ? "Only super_admin" : undefined}
                className="px-4 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 transition-colors"
              >
                Assign
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
