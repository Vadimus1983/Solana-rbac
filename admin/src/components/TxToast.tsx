import React from "react";
import type { Toast } from "../types";

function explorerUrl(sig: string, cluster: string): string {
  if (cluster === "devnet") return `https://explorer.solana.com/tx/${sig}?cluster=devnet`;
  if (cluster === "mainnet-beta") return `https://explorer.solana.com/tx/${sig}`;
  return `https://explorer.solana.com/tx/${sig}?cluster=custom&customUrl=http%3A%2F%2Flocalhost%3A8899`;
}

interface Props {
  toast: Toast;
  cluster: string;
}

export default function TxToast({ toast, cluster }: Props) {
  const bg =
    toast.status === "success"
      ? "bg-green-50 border-green-300"
      : toast.status === "error"
      ? "bg-red-50 border-red-300"
      : "bg-white border-gray-200";

  const icon =
    toast.status === "success"
      ? "✓"
      : toast.status === "error"
      ? "✗"
      : "⏳";

  return (
    <div
      className={`flex items-start gap-2 min-w-64 max-w-sm px-4 py-3 rounded-lg border shadow-md text-sm ${bg}`}
    >
      <span className="mt-0.5 font-bold">{icon}</span>
      <div className="flex flex-col gap-1">
        <span>{toast.message}</span>
        {toast.status === "success" && toast.fee !== undefined && (
          <span className="text-gray-500 text-xs">
            Cost: {toast.fee.toLocaleString()} lamports
          </span>
        )}
        {toast.status === "success" && toast.txSig && (
          <a
            href={explorerUrl(toast.txSig, cluster)}
            target="_blank"
            rel="noreferrer"
            className="text-indigo-600 hover:underline text-xs"
          >
            View on Explorer ↗
          </a>
        )}
      </div>
    </div>
  );
}
