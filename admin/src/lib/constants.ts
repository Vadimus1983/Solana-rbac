import { PublicKey } from "@solana/web3.js";

export const PROGRAM_ID = new PublicKey(
  "H4yTMpUrSrb5Etr2FXhoC8NwaGaigLa2B3KpLZtnv9Lf"
);

export const ROLES_PER_CHUNK = 16;
export const PERMS_PER_CHUNK = 32;

export const RPC_ENDPOINT =
  import.meta.env.VITE_RPC_URL ?? "http://localhost:8899";

export const CLUSTER: string =
  import.meta.env.VITE_CLUSTER ?? "localnet";

export const APP_VERSION = "1.0.2";
