import React, { useState, useCallback } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import WalletButton from "./components/WalletButton";
import TxToast from "./components/TxToast";
import Overview from "./pages/Overview";
import Permissions from "./pages/Permissions";
import Roles from "./pages/Roles";
import Users from "./pages/Users";
import { getProgram, fetchOrg, fetchAllRoles, fetchAllPerms, txInitializeOrg } from "./lib/program";
import { findOrgPda } from "./lib/pda";
import type { OrgData, RoleEntry, PermEntry, Toast } from "./types";
import { CLUSTER, APP_VERSION } from "./lib/constants";

type Tab = "overview" | "permissions" | "roles" | "users";

let toastCounter = 0;

export default function App() {
  const { connection } = useConnection();
  const wallet = useWallet();

  const [orgName, setOrgName] = useState("");
  const [orgInput, setOrgInput] = useState("");
  const [orgData, setOrgData] = useState<OrgData | null>(null);
  const [allRoles, setAllRoles] = useState<RoleEntry[]>([]);
  const [allPerms, setAllPerms] = useState<PermEntry[]>([]);
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [creating, setCreating] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((t: Omit<Toast, "id">): number => {
    const id = ++toastCounter;
    setToasts((prev) => [...prev, { ...t, id }]);
    return id;
  }, []);

  const updateToast = useCallback((id: number, update: Partial<Toast>) => {
    setToasts((prev) =>
      prev.map((t) => (t.id === id ? { ...t, ...update } : t))
    );
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 6000);
  }, []);

  const handleCreateOrg = useCallback(async () => {
    if (!orgInput.trim() || !wallet.publicKey) return;
    const name = orgInput.trim();
    setCreating(true);
    const id = addToast({ status: "pending", message: `Creating org "${name}"…` });
    try {
      const program = getProgram(connection, wallet);
      const sig = await txInitializeOrg(program, name, wallet.publicKey, 0);
      updateToast(id, { status: "success", message: `Org "${name}" created`, txSig: sig });
      setOrgName(name);
      await refresh(name);
    } catch (e: any) {
      updateToast(id, { status: "error", message: e?.message ?? "Create org failed" });
    } finally {
      setCreating(false);
    }
  }, [orgInput, wallet, connection, addToast, updateToast]);

  const refresh = useCallback(async (name: string) => {
    if (!wallet.connected || !wallet.publicKey) return;
    setLoading(true);
    setError(null);
    setNotFound(false);
    try {
      const program = getProgram(connection, wallet);
      const org = await fetchOrg(program, wallet.publicKey!, name);
      const [orgPda] = findOrgPda(org.originalAdmin, name);
      const roles = await fetchAllRoles(program, orgPda, org.roleCount);
      const perms = await fetchAllPerms(
        program,
        orgPda,
        org.nextPermissionIndex
      );
      setOrgData(org);
      setAllRoles(roles);
      setAllPerms(perms);
    } catch (e: any) {
      const msg: string = e?.message ?? "Failed to load org";
      if (msg.includes("does not exist") || msg.includes("Account does not exist")) {
        setNotFound(true);
        setError(null);
      } else if (msg.includes("buffer") || msg.includes("Buffer") || msg.includes("borsh")) {
        setError(
          "Account data could not be decoded (schema mismatch). This often happens with stale validator data. Try: 1) Stop the validator (Ctrl+C), 2) Delete the test-ledger folder in WSL, 3) Restart solana-test-validator, 4) Run anchor build && anchor deploy, 5) Create a new organization."
        );
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }, [connection, wallet]);

  const handleLoad = useCallback(async () => {
    if (!orgInput.trim()) return;
    const name = orgInput.trim();
    setOrgName(name);
    await refresh(name);
  }, [orgInput, refresh]);

  const handleRefresh = useCallback(() => {
    if (orgName) refresh(orgName);
  }, [orgName, refresh]);

  const tabClasses = (t: Tab) =>
    `px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
      tab === t
        ? "border-indigo-500 text-indigo-600"
        : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
    }`;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between">
        <div className="flex items-baseline gap-2">
          <h1 className="text-lg font-bold text-gray-900">RBAC Admin Panel</h1>
          <span className="text-xs font-mono text-gray-400">v{APP_VERSION}</span>
        </div>
        <WalletButton />
      </header>

      {/* Org loader */}
      <div className="max-w-6xl mx-auto px-6 py-4">
        <div className="flex gap-2 items-center">
          <input
            type="text"
            className="border border-gray-300 rounded px-3 py-1.5 text-sm flex-1 max-w-xs focus:outline-none focus:ring-2 focus:ring-indigo-300"
            placeholder="Organization name"
            value={orgInput}
            onChange={(e) => setOrgInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleLoad()}
          />
          <button
            onClick={handleLoad}
            disabled={!wallet.connected || loading}
            className="px-4 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            Load Org
          </button>
          {orgName && (
            <button
              onClick={handleRefresh}
              disabled={loading}
              className="px-3 py-1.5 bg-gray-200 text-gray-700 text-sm rounded hover:bg-gray-300 disabled:opacity-50 transition-colors"
            >
              Refresh
            </button>
          )}
          {loading && (
            <span className="text-sm text-gray-500 animate-pulse">
              Loading…
            </span>
          )}
        </div>
        {error && (
          <p className="mt-2 text-sm text-red-600">{error}</p>
        )}
        {notFound && (
          <div className="mt-3 flex items-center gap-3 p-3 bg-amber-50 border border-amber-200 rounded-lg text-sm">
            <span className="text-amber-700">
              No organization named <span className="font-mono font-semibold">"{orgInput.trim()}"</span> found.
            </span>
            <button
              onClick={handleCreateOrg}
              disabled={creating || !wallet.connected}
              className="px-3 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors whitespace-nowrap"
            >
              {creating ? "Creating…" : "Create it"}
            </button>
          </div>
        )}
        {!wallet.connected && (
          <p className="mt-2 text-sm text-gray-500">
            Connect your wallet to get started.
          </p>
        )}
      </div>

      {/* Tabs */}
      {orgData && (
        <div className="max-w-6xl mx-auto px-6">
          <div className="border-b border-gray-200 flex gap-4">
            <button className={tabClasses("overview")} onClick={() => setTab("overview")}>
              Overview
            </button>
            <button className={tabClasses("permissions")} onClick={() => setTab("permissions")}>
              Permissions ({allPerms.length})
            </button>
            <button className={tabClasses("roles")} onClick={() => setTab("roles")}>
              Roles ({allRoles.length})
            </button>
            <button className={tabClasses("users")} onClick={() => setTab("users")}>
              Users
            </button>
          </div>

          <div className="py-4">
            {tab === "overview" && (
              <Overview
                orgName={orgName}
                orgData={orgData}
                allRoles={allRoles}
                wallet={wallet}
                connection={connection}
                onRefresh={handleRefresh}
                addToast={addToast}
                updateToast={updateToast}
                cluster={CLUSTER}
              />
            )}
            {tab === "permissions" && (
              <Permissions
                orgName={orgName}
                orgData={orgData}
                allPerms={allPerms}
                allRoles={allRoles}
                wallet={wallet}
                connection={connection}
                onRefresh={handleRefresh}
                addToast={addToast}
                updateToast={updateToast}
                cluster={CLUSTER}
              />
            )}
            {tab === "users" && (
              <Users
                orgName={orgName}
                orgData={orgData}
                allRoles={allRoles}
                allPerms={allPerms}
                wallet={wallet}
                connection={connection}
                addToast={addToast}
                updateToast={updateToast}
              />
            )}
            {tab === "roles" && (
              <Roles
                orgName={orgName}
                orgData={orgData}
                allRoles={allRoles}
                allPerms={allPerms}
                wallet={wallet}
                connection={connection}
                onRefresh={handleRefresh}
                addToast={addToast}
                updateToast={updateToast}
                cluster={CLUSTER}
              />
            )}
          </div>
        </div>
      )}

      {/* Toast container */}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {toasts.map((t) => (
          <TxToast key={t.id} toast={t} cluster={CLUSTER} />
        ))}
      </div>
    </div>
  );
}
