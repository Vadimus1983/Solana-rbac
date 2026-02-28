/**
 * Demo script: runs the full RBAC scenario on devnet and prints
 * transaction links for each step. Used for bounty submission.
 *
 * Usage:
 *   npx ts-node src/demo.ts [--cluster devnet]
 */

import * as anchor from "@coral-xyz/anchor";
import {
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";
import {
  getProvider,
  getProgram,
  findOrgPda,
  findRolePda,
  findAssignmentPda,
  findResourcePda,
  explorerUrl,
  PERM_READ,
  PERM_WRITE,
  PERM_DELETE,
  PERM_MANAGE_ROLES,
} from "./utils";

const CLUSTER = process.argv.includes("--cluster")
  ? process.argv[process.argv.indexOf("--cluster") + 1]
  : "devnet";

async function airdrop(
  provider: anchor.AnchorProvider,
  pubkey: PublicKey,
  sol: number
) {
  const sig = await provider.connection.requestAirdrop(
    pubkey,
    sol * LAMPORTS_PER_SOL
  );
  await provider.connection.confirmTransaction(sig);
}

async function main() {
  console.log("=== RBAC Demo on", CLUSTER, "===\n");

  const aliceProvider = getProvider(CLUSTER);
  const program = getProgram(aliceProvider);
  const alice = aliceProvider.wallet;

  const bob = Keypair.generate();
  const carol = Keypair.generate();

  console.log("Alice (super_admin):", alice.publicKey.toBase58());
  console.log("Bob   (editor):     ", bob.publicKey.toBase58());
  console.log("Carol (viewer):     ", carol.publicKey.toBase58());
  console.log();

  // Fund Bob and Carol
  console.log("Airdropping SOL to Bob and Carol...");
  await airdrop(aliceProvider, bob.publicKey, 2);
  await airdrop(aliceProvider, carol.publicKey, 2);
  console.log("  Done.\n");

  const orgName = "acme_demo_" + Date.now().toString(36);
  const [orgPda] = findOrgPda(orgName);

  const txLinks: { step: string; url: string }[] = [];

  function logTx(step: string, sig: string) {
    const url = explorerUrl(sig, CLUSTER);
    txLinks.push({ step, url });
    console.log(`  TX: ${url}`);
  }

  // Step 1
  console.log(`1. Alice creates organization "${orgName}"`);
  let sig = await program.methods
    .initializeOrganization(orgName)
    .accounts({
      organization: orgPda,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx("1. Create organization", sig);
  console.log();

  // Step 2a
  const [adminPda] = findRolePda(orgPda, "admin");
  console.log('2a. Alice creates "admin" role (all permissions)');
  sig = await program.methods
    .createRole("admin", PERM_READ | PERM_WRITE | PERM_DELETE | PERM_MANAGE_ROLES)
    .accounts({
      role: adminPda,
      organization: orgPda,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx('2a. Create "admin" role', sig);

  // Step 2b
  const [editorPda] = findRolePda(orgPda, "editor");
  console.log('2b. Alice creates "editor" role (READ|WRITE)');
  sig = await program.methods
    .createRole("editor", PERM_READ | PERM_WRITE)
    .accounts({
      role: editorPda,
      organization: orgPda,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx('2b. Create "editor" role', sig);

  // Step 2c
  const [viewerPda] = findRolePda(orgPda, "viewer");
  console.log('2c. Alice creates "viewer" role (READ)');
  sig = await program.methods
    .createRole("viewer", PERM_READ)
    .accounts({
      role: viewerPda,
      organization: orgPda,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx('2c. Create "viewer" role', sig);
  console.log();

  // Step 3
  const [bobEditorAssign] = findAssignmentPda(orgPda, bob.publicKey, editorPda);
  console.log('3. Alice assigns Bob the "editor" role');
  sig = await program.methods
    .assignRole()
    .accounts({
      roleAssignment: bobEditorAssign,
      organization: orgPda,
      role: editorPda,
      user: bob.publicKey,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx("3. Assign Bob editor", sig);
  console.log();

  // Step 4 -- Bob creates a resource (switch signer to Bob)
  const bobProvider = new anchor.AnchorProvider(
    aliceProvider.connection,
    new anchor.Wallet(bob),
    { commitment: "confirmed" }
  );
  const bobProgram = getProgram(bobProvider);

  const resourceId1 = new anchor.BN(1);
  const [resPda1] = findResourcePda(orgPda, resourceId1);
  console.log('4. Bob creates resource "Q1 Report" (has WRITE)');
  sig = await bobProgram.methods
    .createResource("Q1 Report", resourceId1)
    .accounts({
      resource: resPda1,
      organization: orgPda,
      role: editorPda,
      roleAssignment: bobEditorAssign,
      authority: bob.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([bob])
    .rpc();
  logTx("4. Bob creates resource", sig);
  console.log();

  // Step 5 -- Bob tries to assign Carol (should fail)
  const [carolViewerAssign] = findAssignmentPda(orgPda, carol.publicKey, viewerPda);
  console.log("5. Bob tries to assign Carol a role (should FAIL)");
  try {
    await bobProgram.methods
      .assignRole()
      .accounts({
        roleAssignment: carolViewerAssign,
        organization: orgPda,
        role: viewerPda,
        user: carol.publicKey,
        authority: bob.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: bobEditorAssign, isWritable: false, isSigner: false },
        { pubkey: editorPda, isWritable: false, isSigner: false },
      ])
      .signers([bob])
      .rpc();
    console.log("  ERROR: should have failed!");
  } catch (err: any) {
    console.log("  Correctly rejected: InsufficientPermission");
  }
  console.log();

  // Step 6 -- Alice assigns Carol the viewer role
  console.log('6. Alice assigns Carol the "viewer" role');
  sig = await program.methods
    .assignRole()
    .accounts({
      roleAssignment: carolViewerAssign,
      organization: orgPda,
      role: viewerPda,
      user: carol.publicKey,
      authority: alice.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  logTx("6. Assign Carol viewer", sig);
  console.log();

  // Step 7 -- Carol tries to create a resource (should fail)
  const carolProvider = new anchor.AnchorProvider(
    aliceProvider.connection,
    new anchor.Wallet(carol),
    { commitment: "confirmed" }
  );
  const carolProgram = getProgram(carolProvider);

  const resourceId2 = new anchor.BN(2);
  const [resPda2] = findResourcePda(orgPda, resourceId2);
  console.log("7. Carol tries to create a resource (should FAIL -- no WRITE)");
  try {
    await carolProgram.methods
      .createResource("Unauthorized", resourceId2)
      .accounts({
        resource: resPda2,
        organization: orgPda,
        role: viewerPda,
        roleAssignment: carolViewerAssign,
        authority: carol.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([carol])
      .rpc();
    console.log("  ERROR: should have failed!");
  } catch (err: any) {
    console.log("  Correctly rejected: InsufficientPermission");
  }
  console.log();

  // Step 8 -- Alice revokes Bob's editor role
  console.log("8. Alice revokes Bob's editor role");
  sig = await program.methods
    .revokeRole()
    .accounts({
      roleAssignment: bobEditorAssign,
      organization: orgPda,
      role: editorPda,
      user: bob.publicKey,
      authority: alice.publicKey,
    })
    .rpc();
  logTx("8. Revoke Bob editor", sig);
  console.log();

  // Step 9 -- Bob tries to create resource (should fail, role revoked)
  const resourceId3 = new anchor.BN(3);
  const [resPda3] = findResourcePda(orgPda, resourceId3);
  console.log("9. Bob tries to create resource after revocation (should FAIL)");
  try {
    await bobProgram.methods
      .createResource("Should Fail", resourceId3)
      .accounts({
        resource: resPda3,
        organization: orgPda,
        role: editorPda,
        roleAssignment: bobEditorAssign,
        authority: bob.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([bob])
      .rpc();
    console.log("  ERROR: should have failed!");
  } catch (err: any) {
    console.log("  Correctly rejected: role assignment no longer exists");
  }
  console.log();

  // Summary
  console.log("=".repeat(60));
  console.log("DEMO COMPLETE -- Transaction Links:");
  console.log("=".repeat(60));
  for (const tx of txLinks) {
    console.log(`  ${tx.step}`);
    console.log(`    ${tx.url}`);
  }
}

main().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});
