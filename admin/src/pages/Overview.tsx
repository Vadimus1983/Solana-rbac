import React, { useState, useEffect } from "react";
import type { OrgData, RoleEntry, Toast } from "../types";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import { Connection } from "@solana/web3.js";
import OrgStateBadge from "../components/OrgStateBadge";
import StateMachineBar from "../components/StateMachineBar";
import {
  getProgram,
  fetchTxFee,
  fetchAllUserAccounts,
  txBeginUpdate,
  txCommitUpdate,
  txFinishUpdate,
  txRecomputeRole,
  txProcessRecomputeUser,
} from "../lib/program";
import { findOrgPda } from "../lib/pda";

interface Props {
  orgName: string;
  orgData: OrgData;
  allRoles: RoleEntry[];
  wallet: WalletContextState;
  connection: Connection;
  onRefresh: () => void;
  addToast: (t: Omit<Toast, "id">) => number;
  updateToast: (id: number, update: Partial<Toast>) => void;
  cluster?: string;
}

function shorten(pk: string): string {
  return pk.slice(0, 6) + "…" + pk.slice(-4);
}

function Step({
  n,
  done,
  children,
}: {
  n: number;
  done?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="flex gap-3 items-start">
      <div
        className={`mt-0.5 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
          done
            ? "bg-green-500 text-white"
            : "bg-white border-2 border-gray-300 text-gray-500"
        }`}
      >
        {done ? "✓" : n}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

export default function Overview({
  orgName,
  orgData,
  allRoles,
  wallet,
  connection,
  onRefresh,
  addToast,
  updateToast,
}: Props) {
  const isSuperAdmin =
    wallet.publicKey?.toBase58() === orgData.superAdmin.toBase58();

  const [stateBusy, setStateBusy] = useState(false);
  const [recomputingRoles, setRecomputingRoles] = useState(false);
  const [recomputingUsers, setRecomputingUsers] = useState(false);
  const [roleProgress, setRoleProgress] = useState("");
  const [userProgress, setUserProgress] = useState("");
  const [rolesRecomputed, setRolesRecomputed] = useState(false);
  const [usersRecomputed, setUsersRecomputed] = useState(false);

  // Reset recomputed flags whenever the org transitions to a new state.
  useEffect(() => {
    setRolesRecomputed(false);
    setUsersRecomputed(false);
  }, [orgData.state]);

  const activeRoles = allRoles.filter((r) => r.active);
  // Commit is safe even without recompute when there are no active roles.
  const canCommit = rolesRecomputed || activeRoles.length === 0;

  const runState = async (label: string, fn: () => Promise<string>) => {
    setStateBusy(true);
    const id = addToast({ status: "pending", message: `Sending ${label}…` });
    try {
      const sig = await fn();
      const fee = await fetchTxFee(connection, sig);
      updateToast(id, { status: "success", message: `${label} confirmed`, txSig: sig, fee });
      onRefresh();
    } catch (e: any) {
      updateToast(id, { status: "error", message: e?.message ?? `${label} failed` });
    } finally {
      setStateBusy(false);
    }
  };

  const handleBeginUpdate = () => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    runState("Begin Update", () =>
      txBeginUpdate(program, orgName, wallet.publicKey!)
    );
  };

  const handleCommitUpdate = () => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    runState("Commit Update", () =>
      txCommitUpdate(program, orgName, wallet.publicKey!)
    );
  };

  const handleFinishUpdate = () => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    runState("Finish Update", () =>
      txFinishUpdate(program, orgName, wallet.publicKey!)
    );
  };

  const handleRecomputeAllRoles = async () => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    if (activeRoles.length === 0) {
      addToast({ status: "success", message: "No active roles to recompute" });
      setRolesRecomputed(true);
      return;
    }
    setRecomputingRoles(true);
    setRoleProgress("");
    let failed = 0;
    for (let i = 0; i < activeRoles.length; i++) {
      const role = activeRoles[i];
      setRoleProgress(`Role ${i + 1}/${activeRoles.length}: "${role.name}"`);
      try {
        await txRecomputeRole(
          program,
          orgName,
          role.topoIndex,
          role.children,
          role.directPermissions,
          wallet.publicKey!
        );
      } catch (e: any) {
        failed++;
        addToast({
          status: "error",
          message: `Recompute role #${role.topoIndex} failed: ${e?.message ?? "unknown"}`,
        });
      }
    }
    setRecomputingRoles(false);
    setRoleProgress("");
    if (failed === 0) {
      addToast({ status: "success", message: `All ${activeRoles.length} roles recomputed` });
      setRolesRecomputed(true);
    }
    onRefresh();
  };

  const handleRecomputeAllUsers = async () => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    const [orgPda] = findOrgPda(orgName);

    setRecomputingUsers(true);
    setUserProgress("Fetching user accounts…");

    let users;
    try {
      users = await fetchAllUserAccounts(program, orgPda);
    } catch (e: any) {
      addToast({ status: "error", message: `Failed to fetch users: ${e?.message}` });
      setRecomputingUsers(false);
      setUserProgress("");
      return;
    }

    if (users.length === 0) {
      addToast({ status: "success", message: "No user accounts to recompute" });
      setRecomputingUsers(false);
      setUserProgress("");
      setUsersRecomputed(true);
      return;
    }

    let failed = 0;
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      const short = user.user.toBase58().slice(0, 6) + "…";
      setUserProgress(`User ${i + 1}/${users.length}: ${short}`);
      try {
        await txProcessRecomputeUser(program, orgName, user, allRoles, wallet.publicKey!);
      } catch (e: any) {
        failed++;
        addToast({
          status: "error",
          message: `Recompute user ${short} failed: ${e?.message ?? "unknown"}`,
        });
      }
    }
    setRecomputingUsers(false);
    setUserProgress("");
    if (failed === 0) {
      addToast({ status: "success", message: `All ${users.length} users recomputed` });
      setUsersRecomputed(true);
    }
    onRefresh();
  };

  const busy = stateBusy || recomputingRoles || recomputingUsers;

  return (
    <div className="space-y-6">
      {/* Org info card */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
        <div className="flex items-center gap-3 mb-4">
          <h2 className="text-xl font-bold text-gray-900">{orgName}</h2>
          <OrgStateBadge state={orgData.state} />
          {!isSuperAdmin && (
            <span className="text-xs text-gray-400">(view-only — not super_admin)</span>
          )}
        </div>
        <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
          <div>
            <dt className="text-gray-500">Super Admin</dt>
            <dd className="font-mono text-gray-800 mt-0.5" title={orgData.superAdmin.toBase58()}>
              {shorten(orgData.superAdmin.toBase58())}
            </dd>
          </div>
          <div>
            <dt className="text-gray-500">Member Count</dt>
            <dd className="font-semibold text-gray-800 mt-0.5">
              {orgData.memberCount.toString()}
            </dd>
          </div>
          <div>
            <dt className="text-gray-500">Role Count</dt>
            <dd className="font-semibold text-gray-800 mt-0.5">{orgData.roleCount}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Next Permission Index</dt>
            <dd className="font-semibold text-gray-800 mt-0.5">
              {orgData.nextPermissionIndex}
            </dd>
          </div>
          <div>
            <dt className="text-gray-500">Permissions Version</dt>
            <dd className="font-semibold text-gray-800 mt-0.5">
              {orgData.permissionsVersion.toString()}
            </dd>
          </div>
        </dl>
      </div>

      {/* Workflow */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
        <h3 className="font-semibold text-gray-900 mb-4">Update Workflow</h3>
        <StateMachineBar state={orgData.state} />

        {/* ── Idle ── */}
        {orgData.state === "idle" && isSuperAdmin && (
          <div className="mt-5 p-4 bg-gray-50 rounded-lg border border-gray-200">
            <p className="text-sm text-gray-600 mb-3">
              Start an update session to create or modify permissions, roles, and assignments.
            </p>
            <button
              onClick={handleBeginUpdate}
              disabled={busy || !wallet.connected}
              className="px-4 py-2 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {stateBusy ? "Sending…" : "Begin Update"}
            </button>
          </div>
        )}

        {/* ── Updating ── */}
        {orgData.state === "updating" && isSuperAdmin && (
          <div className="mt-5 p-4 bg-yellow-50 rounded-lg border border-yellow-200 space-y-4">
            <p className="text-sm font-medium text-yellow-900">
              Follow these steps in order:
            </p>

            <Step n={1}>
              <p className="text-sm font-medium text-gray-800">Edit permissions &amp; roles</p>
              <p className="text-xs text-gray-500 mt-0.5">
                Use the <strong>Permissions</strong> and <strong>Roles</strong> tabs to
                create, delete, or modify assignments.
              </p>
            </Step>

            <Step n={2} done={rolesRecomputed}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-800">Recompute all roles</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Merges direct permissions + child role permissions into each role's
                    effective permissions.
                  </p>
                  {recomputingRoles && roleProgress && (
                    <p className="text-xs text-indigo-600 mt-1 animate-pulse">{roleProgress}</p>
                  )}
                </div>
                <button
                  onClick={handleRecomputeAllRoles}
                  disabled={busy || !wallet.connected}
                  className="shrink-0 px-3 py-1.5 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {recomputingRoles
                    ? "Recomputing…"
                    : rolesRecomputed
                    ? "Recompute Again"
                    : `Recompute ${activeRoles.length} Role${activeRoles.length !== 1 ? "s" : ""}`}
                </button>
              </div>
            </Step>

            <Step n={3} done={false}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-800">Commit update</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Locks in the changes and moves to Recomputing state.
                  </p>
                  {!canCommit && (
                    <p className="text-xs text-amber-600 mt-1">
                      Complete step 2 first.
                    </p>
                  )}
                </div>
                <button
                  onClick={handleCommitUpdate}
                  disabled={busy || !canCommit || !wallet.connected}
                  title={!canCommit ? "Recompute roles first (step 2)" : undefined}
                  className="shrink-0 px-3 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {stateBusy ? "Sending…" : "Commit Update"}
                </button>
              </div>
            </Step>
          </div>
        )}

        {/* ── Recomputing ── */}
        {orgData.state === "recomputing" && isSuperAdmin && (
          <div className="mt-5 p-4 bg-blue-50 rounded-lg border border-blue-200 space-y-4">
            <p className="text-sm font-medium text-blue-900">
              Follow these steps in order:
            </p>

            <Step n={1} done={usersRecomputed}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-800">Recompute all users</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Propagates the updated role permissions to every user's permission cache.
                  </p>
                  {recomputingUsers && userProgress && (
                    <p className="text-xs text-indigo-600 mt-1 animate-pulse">{userProgress}</p>
                  )}
                </div>
                <button
                  onClick={handleRecomputeAllUsers}
                  disabled={busy || !wallet.connected}
                  className="shrink-0 px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {recomputingUsers
                    ? "Recomputing…"
                    : usersRecomputed
                    ? "Recompute Again"
                    : "Recompute All Users"}
                </button>
              </div>
            </Step>

            <Step n={2} done={false}>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-800">Finish update</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Returns the organization to Idle state.
                  </p>
                  {!usersRecomputed && (
                    <p className="text-xs text-amber-600 mt-1">
                      Complete step 1 first.
                    </p>
                  )}
                </div>
                <button
                  onClick={handleFinishUpdate}
                  disabled={busy || !usersRecomputed || !wallet.connected}
                  title={!usersRecomputed ? "Recompute users first (step 1)" : undefined}
                  className="shrink-0 px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {stateBusy ? "Sending…" : "Finish Update"}
                </button>
              </div>
            </Step>
          </div>
        )}

        {!isSuperAdmin && (
          <p className="mt-4 text-xs text-gray-400">
            Workflow controls are only available to the super_admin.
          </p>
        )}
      </div>
    </div>
  );
}
