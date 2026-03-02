import React from "react";
import { useWalletModal } from "@solana/wallet-adapter-react-ui";
import { useWallet } from "@solana/wallet-adapter-react";

export default function WalletButton() {
  const { connected, publicKey, disconnect } = useWallet();
  const { setVisible } = useWalletModal();

  if (connected && publicKey) {
    const short =
      publicKey.toBase58().slice(0, 4) +
      "…" +
      publicKey.toBase58().slice(-4);
    return (
      <button
        onClick={() => disconnect()}
        className="px-3 py-1.5 bg-red-100 text-red-700 text-sm rounded hover:bg-red-200 transition-colors font-mono"
        title="Click to disconnect"
      >
        {short}
      </button>
    );
  }

  return (
    <button
      onClick={() => setVisible(true)}
      className="px-3 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 transition-colors"
    >
      Connect Wallet
    </button>
  );
}
