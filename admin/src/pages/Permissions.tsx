import React, { useState } from "react";
import type { OrgData, PermEntry, RoleEntry, Toast } from "../types";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import { Connection } from "@solana/web3.js";
import Modal from "../components/Modal";
import { bitmaskToIndices } from "../lib/bitmask";
import {
  getProgram,
  txCreatePermission,
  txDeletePermission,
  txRemoveRolePermission,
} from "../lib/program";

interface Props {
  orgName: string;
  orgData: OrgData;
  allPerms: PermEntry[];
  allRoles: RoleEntry[];
  wallet: WalletContextState;
  connection: Connection;
  onRefresh: () => void;
  addToast: (t: Omit<Toast, "id">) => number;
  updateToast: (id: number, update: Partial<Toast>) => void;
  cluster: string;
}

export default function Permissions({
  orgName,
  orgData,
  allPerms,
  allRoles,
  wallet,
  connection,
  onRefresh,
  addToast,
  updateToast,
}: Props) {
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmPerm, setConfirmPerm] = useState<PermEntry | null>(null);
  const [deleteProgress, setDeleteProgress] = useState("");

  const isUpdating = orgData.state === "updating";
  const isSuperAdmin =
    wallet.publicKey?.toBase58() === orgData.superAdmin.toBase58();
  const canWrite = isUpdating && isSuperAdmin && wallet.connected;
  const notUpdatingMsg = "Organization must be in Updating state";

  const run = async (label: string, fn: () => Promise<string>) => {
    const id = addToast({ status: "pending", message: `Sending ${label}…` });
    try {
      const sig = await fn();
      updateToast(id, { status: "success", message: `${label} confirmed`, txSig: sig });
      return true;
    } catch (e: any) {
      updateToast(id, { status: "error", message: e?.message ?? `${label} failed` });
      return false;
    }
  };

  const handleCreate = async () => {
    if (!newName.trim() || !wallet.publicKey) return;
    setBusy(true);
    const program = getProgram(connection, wallet);
    await run("Create Permission", () =>
      txCreatePermission(
        program,
        orgName,
        orgData.nextPermissionIndex,
        wallet.publicKey!,
        newName.trim(),
        newDesc.trim()
      )
    );
    setBusy(false);
    setNewName("");
    setNewDesc("");
    setShowCreate(false);
    onRefresh();
  };

  // Roles that have this permission in their direct_permissions bitmask
  const rolesWithPerm = (permIndex: number): RoleEntry[] =>
    allRoles.filter(
      (r) => r.active && bitmaskToIndices(r.directPermissions).includes(permIndex)
    );

  const handleDeleteConfirmed = async () => {
    if (!confirmPerm || !wallet.publicKey) return;
    setBusy(true);
    const program = getProgram(connection, wallet);
    const affected = rolesWithPerm(confirmPerm.index);

    // Step 1: remove permission from every role that has it
    for (const role of affected) {
      setDeleteProgress(`Removing from role "${role.name}" (${affected.indexOf(role) + 1}/${affected.length})…`);
      const ok = await run(
        `Remove perm #${confirmPerm.index} from role #${role.topoIndex}`,
        () =>
          txRemoveRolePermission(
            program,
            orgName,
            role.topoIndex,
            confirmPerm.index,
            wallet.publicKey!
          )
      );
      if (!ok) {
        setDeleteProgress("");
        setBusy(false);
        return;
      }
    }

    // Step 2: soft-delete the permission
    setDeleteProgress("Deleting permission…");
    await run(`Delete Permission #${confirmPerm.index}`, () =>
      txDeletePermission(program, orgName, confirmPerm.index, wallet.publicKey!)
    );

    setDeleteProgress("");
    setBusy(false);
    setConfirmPerm(null);
    onRefresh();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">Permissions</h2>
        <button
          onClick={() => setShowCreate(true)}
          disabled={!canWrite || busy}
          title={!isUpdating ? notUpdatingMsg : !isSuperAdmin ? "Only super_admin" : undefined}
          className="px-3 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          + Create Permission
        </button>
      </div>

      {allPerms.length === 0 ? (
        <p className="text-gray-500 text-sm">No permissions yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white rounded-xl border border-gray-200 shadow-sm text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Index</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Created By</th>
                <th className="px-4 py-3">Assigned To</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {allPerms.map((p) => {
                const affected = rolesWithPerm(p.index);
                return (
                  <tr
                    key={p.index}
                    className="border-b border-gray-50 hover:bg-gray-50 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-gray-600">{p.index}</td>
                    <td className="px-4 py-3 font-medium text-gray-900">
                      {p.active
                        ? p.name
                        : <span className="line-through text-gray-400">{p.name}</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 max-w-xs truncate">{p.description}</td>
                    <td className="px-4 py-3 font-mono text-gray-500 text-xs">
                      {p.createdBy.toBase58().slice(0, 6)}…{p.createdBy.toBase58().slice(-4)}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-600">
                      {affected.length === 0 ? (
                        <span className="text-gray-400">—</span>
                      ) : (
                        <span className="text-amber-700 font-medium">
                          {affected.map((r) => r.name).join(", ")}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {p.active ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Active
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-700">
                          Inactive
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {p.active && (
                        <button
                          onClick={() => setConfirmPerm(p)}
                          disabled={!canWrite || busy}
                          title={!isUpdating ? notUpdatingMsg : !isSuperAdmin ? "Only super_admin" : undefined}
                          className="px-2 py-1 text-xs text-red-600 border border-red-200 rounded hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Delete confirmation modal */}
      {confirmPerm && (
        <Modal
          title={`Delete Permission #${confirmPerm.index}`}
          onClose={() => !busy && setConfirmPerm(null)}
        >
          <div className="space-y-4">
            <p className="text-sm text-gray-700">
              You are about to delete{" "}
              <span className="font-semibold">"{confirmPerm.name}"</span>.
            </p>

            {rolesWithPerm(confirmPerm.index).length > 0 ? (
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-sm">
                <p className="font-medium text-amber-800 mb-2">
                  This permission is assigned to the following roles:
                </p>
                <ul className="space-y-1">
                  {rolesWithPerm(confirmPerm.index).map((r) => (
                    <li key={r.topoIndex} className="text-amber-700 font-mono text-xs">
                      #{r.topoIndex} — {r.name}
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-amber-700 text-xs">
                  It will be <strong>automatically removed from these roles</strong> before deletion,
                  so recompute produces correct results.
                </p>
              </div>
            ) : (
              <p className="text-sm text-gray-500">
                No active roles are using this permission.
              </p>
            )}

            {deleteProgress && (
              <p className="text-xs text-indigo-600 animate-pulse">{deleteProgress}</p>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button
                onClick={() => setConfirmPerm(null)}
                disabled={busy}
                className="px-4 py-1.5 text-sm text-gray-600 border border-gray-300 rounded hover:bg-gray-50 disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteConfirmed}
                disabled={busy}
                className="px-4 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
              >
                {busy ? "Processing…" : "Confirm Delete"}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Create permission modal */}
      {showCreate && (
        <Modal title="Create Permission" onClose={() => setShowCreate(false)}>
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Name <span className="text-gray-400">(max 32 chars)</span>
              </label>
              <input
                type="text"
                maxLength={32}
                className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. read_documents"
                autoFocus
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Description <span className="text-gray-400">(max 128 chars)</span>
              </label>
              <textarea
                maxLength={128}
                rows={3}
                className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300 resize-none"
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Allows reading documents"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-1.5 text-sm text-gray-600 border border-gray-300 rounded hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!newName.trim() || busy}
                className="px-4 py-1.5 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
              >
                {busy ? "Sending…" : "Create"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
