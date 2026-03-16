import React, { useState, useEffect } from "react";
import type { OrgData, RoleEntry, PermEntry, Toast } from "../types";
import type { WalletContextState } from "@solana/wallet-adapter-react";
import { Connection } from "@solana/web3.js";
import Modal from "../components/Modal";
import { bitmaskToIndices } from "../lib/bitmask";
import {
  getProgram,
  fetchTxFee,
  txCreateRole,
  txDeleteRole,
  txAddRolePermission,
  txRemoveRolePermission,
  txAddChildRole,
  txRemoveChildRole,
  txRecomputeRole,
} from "../lib/program";

interface Props {
  orgName: string;
  orgData: OrgData;
  allRoles: RoleEntry[];
  allPerms: PermEntry[];
  wallet: WalletContextState;
  connection: Connection;
  onRefresh: () => void;
  addToast: (t: Omit<Toast, "id">) => number;
  updateToast: (id: number, update: Partial<Toast>) => void;
  cluster: string;
}

export default function Roles({
  orgName,
  orgData,
  allRoles,
  allPerms,
  wallet,
  connection,
  onRefresh,
  addToast,
  updateToast,
}: Props) {
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [editRole, setEditRole] = useState<RoleEntry | null>(null);
  const [busy, setBusy] = useState(false);

  // Perm/child selects for edit panel
  const [addPermIdx, setAddPermIdx] = useState<number | "">("");
  const [addChildIdx, setAddChildIdx] = useState<number | "">("");

  // Keep editRole in sync when allRoles refreshes after an operation.
  useEffect(() => {
    if (editRole !== null) {
      const fresh = allRoles.find((r) => r.topoIndex === editRole.topoIndex);
      if (fresh) setEditRole(fresh);
    }
  }, [allRoles]);

  const isUpdating = orgData.state === "updating";
  const isSuperAdmin =
    wallet.publicKey?.toBase58() === orgData.superAdmin.toBase58();
  const canWrite = isUpdating && isSuperAdmin && wallet.connected;
  const notUpdatingMsg = "Organization must be in Updating state";

  const run = async (label: string, fn: () => Promise<string>) => {
    setBusy(true);
    const id = addToast({ status: "pending", message: `Sending ${label}…` });
    try {
      const sig = await fn();
      const fee = await fetchTxFee(connection, sig);
      updateToast(id, { status: "success", message: `${label} confirmed`, txSig: sig, fee });
      onRefresh();
    } catch (e: any) {
      updateToast(id, { status: "error", message: e?.message ?? `${label} failed` });
    } finally {
      setBusy(false);
    }
  };

  const handleCreate = async () => {
    if (!newName.trim() || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run("Create Role", () =>
      txCreateRole(
        program,
        orgData.originalAdmin,
        orgName,
        orgData.roleCount,
        wallet.publicKey!,
        newName.trim(),
        newDesc.trim()
      )
    );
    setNewName("");
    setNewDesc("");
    setShowCreate(false);
  };

  const handleDelete = async (role: RoleEntry) => {
    if (!wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Delete Role #${role.topoIndex}`, () =>
      txDeleteRole(program, orgData.originalAdmin, orgName, role.topoIndex, wallet.publicKey!)
    );
  };

  const handleAddPerm = async () => {
    if (editRole === null || addPermIdx === "" || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Add Permission ${addPermIdx} to Role ${editRole.topoIndex}`, () =>
      txAddRolePermission(
        program,
        orgData.originalAdmin,
        orgName,
        editRole.topoIndex,
        addPermIdx as number,
        wallet.publicKey!
      )
    );
    setAddPermIdx("");
  };

  const handleRemovePerm = async (permIdx: number) => {
    if (editRole === null || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Remove Permission ${permIdx} from Role ${editRole.topoIndex}`, () =>
      txRemoveRolePermission(
        program,
        orgData.originalAdmin,
        orgName,
        editRole.topoIndex,
        permIdx,
        wallet.publicKey!
      )
    );
  };

  const handleAddChild = async () => {
    if (editRole === null || addChildIdx === "" || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Add Child ${addChildIdx} to Role ${editRole.topoIndex}`, () =>
      txAddChildRole(
        program,
        orgData.originalAdmin,
        orgName,
        editRole.topoIndex,
        addChildIdx as number,
        wallet.publicKey!
      )
    );
    setAddChildIdx("");
  };

  const handleRemoveChild = async (childIdx: number) => {
    if (editRole === null || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Remove Child ${childIdx} from Role ${editRole.topoIndex}`, () =>
      txRemoveChildRole(
        program,
        orgData.originalAdmin,
        orgName,
        editRole.topoIndex,
        childIdx,
        wallet.publicKey!
      )
    );
  };

  const handleRecompute = async () => {
    if (editRole === null || !wallet.publicKey) return;
    const program = getProgram(connection, wallet);
    await run(`Recompute Role ${editRole.topoIndex}`, () =>
      txRecomputeRole(
        program,
        orgData.originalAdmin,
        orgName,
        editRole.topoIndex,
        editRole.children,
        editRole.directPermissions,
        wallet.publicKey!,
        allRoles,
        orgData.nextPermissionIndex
      )
    );
  };

  // Active perms not already on this role
  const availablePermsForAdd = allPerms.filter(
    (p) =>
      p.active &&
      editRole &&
      !bitmaskToIndices(editRole.directPermissions).includes(p.index)
  );

  // Active roles with lower topo_index (potential children)
  const availableChildren =
    editRole
      ? allRoles.filter(
          (r) =>
            r.active &&
            r.topoIndex < editRole.topoIndex &&
            !editRole.children.includes(r.topoIndex)
        )
      : [];

  const currentDirectPerms = editRole
    ? bitmaskToIndices(editRole.directPermissions)
    : [];
  const currentEffPerms = editRole
    ? bitmaskToIndices(editRole.effectivePermissions)
    : [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">Roles</h2>
        <button
          onClick={() => setShowCreate(true)}
          disabled={!canWrite || busy}
          title={!isUpdating ? notUpdatingMsg : !isSuperAdmin ? "Only super_admin" : undefined}
          className="px-3 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          + Create Role
        </button>
      </div>

      {allRoles.length === 0 ? (
        <p className="text-gray-500 text-sm">No roles yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white rounded-xl border border-gray-200 shadow-sm text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Index</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Direct Perms</th>
                <th className="px-4 py-3">Effective Perms</th>
                <th className="px-4 py-3">Children</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {allRoles.map((r) => {
                const directPerms = bitmaskToIndices(r.directPermissions);
                const effPerms = bitmaskToIndices(r.effectivePermissions);
                return (
                  <tr
                    key={r.topoIndex}
                    className="border-b border-gray-50 hover:bg-gray-50 transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-gray-600">{r.topoIndex}</td>
                    <td className="px-4 py-3 font-medium text-gray-900">
                      {r.active ? r.name : <span className="line-through text-gray-400">{r.name}</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-600 max-w-xs truncate">{r.description}</td>
                    <td className="px-4 py-3">
                      {r.active ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Active
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-700">
                          Inactive
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-600 font-mono text-xs">
                      {directPerms.length ? directPerms.join(", ") : "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-600 font-mono text-xs">
                      {effPerms.length ? effPerms.join(", ") : "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-600 font-mono text-xs">
                      {r.children.length ? r.children.join(", ") : "—"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5">
                        <button
                          onClick={() => {
                            setEditRole(r);
                            setAddPermIdx("");
                            setAddChildIdx("");
                          }}
                          className="px-2 py-1 text-xs text-indigo-600 border border-indigo-200 rounded hover:bg-indigo-50 transition-colors"
                        >
                          Edit
                        </button>
                        {r.active && (
                          <button
                            onClick={() => handleDelete(r)}
                            disabled={!canWrite || busy}
                            title={!isUpdating ? notUpdatingMsg : !isSuperAdmin ? "Only super_admin" : undefined}
                            className="px-2 py-1 text-xs text-red-600 border border-red-200 rounded hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Role Modal */}
      {showCreate && (
        <Modal title="Create Role" onClose={() => setShowCreate(false)}>
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
                placeholder="e.g. editor"
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
                placeholder="Can edit content"
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

      {/* Edit Role Modal */}
      {editRole && (
        <Modal
          title={`Edit Role: ${editRole.name} (#${editRole.topoIndex})`}
          onClose={() => setEditRole(null)}
        >
          <div className="space-y-5 max-h-[70vh] overflow-y-auto pr-1">
            {!canWrite && (
              <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                {!isUpdating ? notUpdatingMsg : "Only super_admin can modify roles."}
              </p>
            )}

            {/* Permissions section */}
            <div>
              <h4 className="text-sm font-semibold text-gray-800 mb-2">
                Direct Permissions
              </h4>
              {currentDirectPerms.length === 0 ? (
                <p className="text-xs text-gray-400">None</p>
              ) : (
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {currentDirectPerms.map((pi) => {
                    const perm = allPerms.find((p) => p.index === pi);
                    return (
                      <span
                        key={pi}
                        className="flex items-center gap-1 px-2 py-0.5 bg-indigo-50 border border-indigo-200 rounded text-xs text-indigo-700"
                      >
                        {pi}: {perm?.name ?? "unknown"}
                        <button
                          onClick={() => handleRemovePerm(pi)}
                          disabled={!canWrite || busy}
                          className="ml-1 text-indigo-400 hover:text-red-500 disabled:opacity-40 font-bold"
                          title={!canWrite ? notUpdatingMsg : "Remove"}
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
                  className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm disabled:opacity-50"
                  value={addPermIdx}
                  onChange={(e) =>
                    setAddPermIdx(e.target.value === "" ? "" : Number(e.target.value))
                  }
                  disabled={!canWrite || availablePermsForAdd.length === 0}
                >
                  <option value="">— select permission —</option>
                  {availablePermsForAdd.map((p) => (
                    <option key={p.index} value={p.index}>
                      #{p.index}: {p.name}
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleAddPerm}
                  disabled={!canWrite || addPermIdx === "" || busy}
                  className="px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
                >
                  Add
                </button>
              </div>
            </div>

            {/* Effective permissions (readonly) */}
            <div>
              <h4 className="text-sm font-semibold text-gray-800 mb-1">
                Effective Permissions{" "}
                <span className="text-gray-400 font-normal text-xs">(after recompute)</span>
              </h4>
              <p className="text-xs text-gray-600 font-mono">
                {currentEffPerms.length ? currentEffPerms.join(", ") : "—"}
              </p>
            </div>

            {/* Children section */}
            <div>
              <h4 className="text-sm font-semibold text-gray-800 mb-2">
                Child Roles
              </h4>
              {editRole.children.length === 0 ? (
                <p className="text-xs text-gray-400 mb-2">None</p>
              ) : (
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {editRole.children.map((ci) => {
                    const child = allRoles.find((r) => r.topoIndex === ci);
                    return (
                      <span
                        key={ci}
                        className="flex items-center gap-1 px-2 py-0.5 bg-green-50 border border-green-200 rounded text-xs text-green-700"
                      >
                        {ci}: {child?.name ?? "unknown"}
                        <button
                          onClick={() => handleRemoveChild(ci)}
                          disabled={!canWrite || busy}
                          className="ml-1 text-green-400 hover:text-red-500 disabled:opacity-40 font-bold"
                          title={!canWrite ? notUpdatingMsg : "Remove"}
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
                  className="flex-1 border border-gray-300 rounded px-2 py-1 text-sm disabled:opacity-50"
                  value={addChildIdx}
                  onChange={(e) =>
                    setAddChildIdx(e.target.value === "" ? "" : Number(e.target.value))
                  }
                  disabled={!canWrite || availableChildren.length === 0}
                >
                  <option value="">— select child role —</option>
                  {availableChildren.map((r) => (
                    <option key={r.topoIndex} value={r.topoIndex}>
                      #{r.topoIndex}: {r.name}
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleAddChild}
                  disabled={!canWrite || addChildIdx === "" || busy}
                  className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                >
                  Add
                </button>
              </div>
            </div>

            {/* Recompute */}
            <div className="border-t pt-3">
              <button
                onClick={handleRecompute}
                disabled={!canWrite || busy}
                title={!canWrite ? notUpdatingMsg : undefined}
                className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {busy ? "Computing…" : "Recompute Effective Permissions"}
              </button>
              <p className="text-xs text-gray-400 mt-1 text-center">
                Updates effective permissions by merging direct perms + child role perms.
              </p>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
