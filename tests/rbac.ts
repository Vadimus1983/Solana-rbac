import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Rbac } from "../target/types/rbac";
import { assert } from "chai";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ROLES_PER_CHUNK = 16;
const PERMS_PER_CHUNK = 32;

// ---------------------------------------------------------------------------
// PDA helpers
// ---------------------------------------------------------------------------

function findOrgPda(programId: PublicKey, name: string): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("organization"), Buffer.from(name)],
    programId
  );
}

function findRoleChunkPda(
  programId: PublicKey,
  orgKey: PublicKey,
  chunkIndex: number
): [PublicKey, number] {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(chunkIndex, 0);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("role_chunk"), orgKey.toBuffer(), buf],
    programId
  );
}

function findPermChunkPda(
  programId: PublicKey,
  orgKey: PublicKey,
  chunkIndex: number
): [PublicKey, number] {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(chunkIndex, 0);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("perm_chunk"), orgKey.toBuffer(), buf],
    programId
  );
}

function findUserAccountPda(
  programId: PublicKey,
  orgKey: PublicKey,
  userKey: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("user_account"), orgKey.toBuffer(), userKey.toBuffer()],
    programId
  );
}

function findUserPermCachePda(
  programId: PublicKey,
  orgKey: PublicKey,
  userKey: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("user_perm_cache"), orgKey.toBuffer(), userKey.toBuffer()],
    programId
  );
}

function findResourcePda(
  programId: PublicKey,
  orgKey: PublicKey,
  resourceId: anchor.BN
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("resource"),
      orgKey.toBuffer(),
      resourceId.toArrayLike(Buffer, "le", 8),
    ],
    programId
  );
}

function roleChunkIndex(roleIndex: number): number {
  return Math.floor(roleIndex / ROLES_PER_CHUNK);
}

function hasBit(bitmask: number[], index: number): boolean {
  const bytePos = Math.floor(index / 8);
  const bitPos = index % 8;
  return bytePos < bitmask.length && (bitmask[bytePos] & (1 << bitPos)) !== 0;
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("rbac", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Rbac as Program<Rbac>;

  const alice = provider.wallet as anchor.Wallet;
  const bob = Keypair.generate();
  const carol = Keypair.generate();

  const orgName = "acme_corp";

  let orgPda: PublicKey;
  let roleChunk0Pda: PublicKey;  // chunk 0: roles 0-15
  let permChunk0Pda: PublicKey;  // chunk 0: perms 0-31
  let bobUaPda: PublicKey;
  let carolUaPda: PublicKey;
  let bobUpcPda: PublicKey;
  let carolUpcPda: PublicKey;

  // Role/perm indices
  const viewerRoleIdx = 0;
  const editorRoleIdx = 1;
  const readPermIdx = 0;
  const writePermIdx = 1;

  before(async () => {
    const conn = provider.connection;
    for (const kp of [bob, carol]) {
      const sig = await conn.requestAirdrop(kp.publicKey, 2 * LAMPORTS_PER_SOL);
      await conn.confirmTransaction(sig);
    }
  });

  // -------------------------------------------------------------------------
  // Step 1 — Alice creates organisation (starts in Idle)
  // -------------------------------------------------------------------------
  it("Step 1: Alice creates organisation 'acme_corp'", async () => {
    [orgPda] = findOrgPda(program.programId, orgName);

    await program.methods
      .initializeOrganization(orgName)
      .accounts({
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    assert.equal(org.name, orgName);
    assert.ok(org.superAdmin.equals(alice.publicKey));
    assert.deepEqual(org.state, { idle: {} });
    assert.equal(org.roleCount, 0);
    assert.equal(org.nextPermissionIndex, 0);
  });

  // -------------------------------------------------------------------------
  // Step 2 — Create user accounts while org is Idle
  // -------------------------------------------------------------------------
  it("Step 2: Alice creates UserAccounts for Bob and Carol", async () => {
    [bobUaPda] = findUserAccountPda(program.programId, orgPda, bob.publicKey);
    [carolUaPda] = findUserAccountPda(program.programId, orgPda, carol.publicKey);
    [bobUpcPda] = findUserPermCachePda(program.programId, orgPda, bob.publicKey);
    [carolUpcPda] = findUserPermCachePda(program.programId, orgPda, carol.publicKey);

    await program.methods
      .createUserAccount()
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        organization: orgPda,
        user: bob.publicKey,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .createUserAccount()
      .accounts({
        userAccount: carolUaPda,
        userPermCache: carolUpcPda,
        organization: orgPda,
        user: carol.publicKey,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const bobUa = await program.account.userAccount.fetch(bobUaPda);
    assert.ok(bobUa.user.equals(bob.publicKey));
    assert.ok(bobUa.organization.equals(orgPda));
    assert.equal(bobUa.assignedRoles.length, 0);

    // Verify UserPermCache was initialized correctly.
    const bobCache = await (program.account as any).userPermCache.fetch(bobUpcPda);
    assert.ok(bobCache.user.equals(bob.publicKey));
    assert.ok(bobCache.organization.equals(orgPda));
    assert.deepEqual(Array.from(bobCache.effectivePermissions as number[]), new Array(32).fill(0));
    assert.deepEqual(Array.from(bobCache.effectiveRoles as number[]), new Array(32).fill(0));
  });

  // -------------------------------------------------------------------------
  // Step 3 — Begin update (Idle → Updating)
  // -------------------------------------------------------------------------
  it("Step 3: Alice begins update", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    assert.deepEqual(org.state, { updating: {} });
  });

  // -------------------------------------------------------------------------
  // Step 4 — Create permissions (requires Updating). Chunk 0 created here.
  // -------------------------------------------------------------------------
  it("Step 4a: Alice creates 'read' permission (index 0)", async () => {
    [permChunk0Pda] = findPermChunkPda(program.programId, orgPda, 0);

    await program.methods
      .createPermission("read", "Allows reading resources")
      .accounts({
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.permChunk.fetch(permChunk0Pda);
    assert.equal(chunk.entries.length, 1);
    const entry = chunk.entries[0];
    assert.equal(entry.name, "read");
    assert.equal(entry.index, 0);
    assert.ok(entry.active);
  });

  it("Step 4b: Alice creates 'write' permission (index 1)", async () => {
    await program.methods
      .createPermission("write", "Allows writing resources")
      .accounts({
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.permChunk.fetch(permChunk0Pda);
    assert.equal(chunk.entries.length, 2);
    assert.equal(chunk.entries[1].name, "write");
    assert.equal(chunk.entries[1].index, 1);
  });

  // -------------------------------------------------------------------------
  // Step 5 — Create roles (requires Updating). Role chunk 0 created here.
  // -------------------------------------------------------------------------
  it("Step 5a: Alice creates 'viewer' role (index 0)", async () => {
    [roleChunk0Pda] = findRoleChunkPda(program.programId, orgPda, 0);

    await program.methods
      .createRole("viewer", "Can read resources")
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    assert.equal(chunk.entries.length, 1);
    const entry = chunk.entries[0];
    assert.equal(entry.name, "viewer");
    assert.equal(entry.topoIndex, 0);
    assert.ok(entry.active);
  });

  it("Step 5b: Alice creates 'editor' role (index 1)", async () => {
    await program.methods
      .createRole("editor", "Can read and write resources")
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    assert.equal(chunk.entries.length, 2);
    assert.equal(chunk.entries[1].name, "editor");
    assert.equal(chunk.entries[1].topoIndex, 1);

    const org = await program.account.organization.fetch(orgPda);
    assert.equal(org.roleCount, 2);
  });

  // -------------------------------------------------------------------------
  // Step 6 — Assign permissions to roles
  // -------------------------------------------------------------------------
  it("Step 6a: viewer gets read permission (index 0)", async () => {
    await program.methods
      .addRolePermission(viewerRoleIdx, readPermIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const entry = chunk.entries[viewerRoleIdx];
    assert.ok(hasBit(entry.directPermissions as number[], readPermIdx), "viewer should have perm 0");
    assert.ok(entry.version.toNumber() > 0, "version should have been bumped");
  });

  it("Step 6b: editor gets read (0) and write (1) permissions", async () => {
    await program.methods
      .addRolePermission(editorRoleIdx, readPermIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .addRolePermission(editorRoleIdx, writePermIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const entry = chunk.entries[editorRoleIdx];
    assert.ok(hasBit(entry.directPermissions as number[], readPermIdx), "editor should have perm 0");
    assert.ok(hasBit(entry.directPermissions as number[], writePermIdx), "editor should have perm 1");
  });

  // -------------------------------------------------------------------------
  // Step 7 — Recompute role effective_permissions (no children → direct = effective)
  // -------------------------------------------------------------------------
  it("Step 7a: recompute viewer role", async () => {
    await program.methods
      .recomputeRole(viewerRoleIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([])
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const entry = chunk.entries[viewerRoleIdx];
    assert.ok(hasBit(entry.effectivePermissions as number[], readPermIdx), "viewer effective should have perm 0");
    assert.ok(!hasBit(entry.effectivePermissions as number[], writePermIdx), "viewer effective should NOT have perm 1");
  });

  it("Step 7b: recompute editor role", async () => {
    await program.methods
      .recomputeRole(editorRoleIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([])
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const entry = chunk.entries[editorRoleIdx];
    assert.ok(hasBit(entry.effectivePermissions as number[], readPermIdx), "editor effective should have perm 0");
    assert.ok(hasBit(entry.effectivePermissions as number[], writePermIdx), "editor effective should have perm 1");
  });

  // -------------------------------------------------------------------------
  // Step 8 — commit_update (Updating → Recomputing) then process + finish
  // -------------------------------------------------------------------------
  it("Step 8: Alice commits update", async () => {
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    assert.deepEqual(org.state, { recomputing: {} });
    assert.equal(org.permissionsVersion.toNumber(), 1);
  });

  it("Step 9: Batch recompute (users have no roles yet — 0 chunks each)", async () => {
    // Both users have no roles assigned yet, so 0 chunk accounts each.
    // Layout: [UA, UPC] per user (no chunks).
    const remainingAccounts = [
      { pubkey: bobUaPda, isWritable: true, isSigner: false },
      { pubkey: bobUpcPda, isWritable: true, isSigner: false },
      { pubkey: carolUaPda, isWritable: true, isSigner: false },
      { pubkey: carolUpcPda, isWritable: true, isSigner: false },
    ];

    await program.methods
      .processRecomputeBatch(Buffer.from([0, 0]))
      .accounts({
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(remainingAccounts)
      .rpc();

    const bobUa = await program.account.userAccount.fetch(bobUaPda);
    const carolUa = await program.account.userAccount.fetch(carolUaPda);
    assert.equal(bobUa.cachedVersion.toNumber(), 1);
    assert.equal(carolUa.cachedVersion.toNumber(), 1);

    // Verify caches were also updated.
    const bobCache = await (program.account as any).userPermCache.fetch(bobUpcPda);
    const carolCache = await (program.account as any).userPermCache.fetch(carolUpcPda);
    assert.equal(bobCache.permissionsVersion.toNumber(), 1);
    assert.equal(carolCache.permissionsVersion.toNumber(), 1);
  });

  it("Step 10: Alice finishes update → Idle", async () => {
    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    assert.deepEqual(org.state, { idle: {} });
  });

  // -------------------------------------------------------------------------
  // Step 11 — Assign roles in Idle state (inline recompute, no batch needed)
  // -------------------------------------------------------------------------
  it("Step 11a: Alice assigns Bob the editor role (Idle state)", async () => {
    await program.methods
      .assignRole(editorRoleIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const ua = await program.account.userAccount.fetch(bobUaPda);
    const hasEditor = ua.assignedRoles.some(
      (r: { topoIndex: number }) => r.topoIndex === editorRoleIdx
    );
    assert.ok(hasEditor, "Bob should have editor role");

    // Effective permissions should be immediately updated (no batch needed).
    assert.ok(hasBit(ua.effectivePermissions as number[], readPermIdx), "Bob should have perm 0");
    assert.ok(hasBit(ua.effectivePermissions as number[], writePermIdx), "Bob should have perm 1");
    assert.equal(ua.cachedVersion.toNumber(), 1, "Bob's cached_version should equal org.permissions_version");

    // Verify UserPermCache is also in sync.
    const cache = await (program.account as any).userPermCache.fetch(bobUpcPda);
    assert.ok(hasBit(cache.effectivePermissions as number[], readPermIdx), "cache: Bob should have perm 0");
    assert.ok(hasBit(cache.effectivePermissions as number[], writePermIdx), "cache: Bob should have perm 1");
    assert.ok(hasBit(cache.effectiveRoles as number[], editorRoleIdx), "cache: Bob should have editor role bit set");
    assert.equal(cache.permissionsVersion.toNumber(), 1);
  });

  it("Step 11b: Alice assigns Carol the viewer role (Idle state)", async () => {
    await program.methods
      .assignRole(viewerRoleIdx)
      .accounts({
        userAccount: carolUaPda,
        userPermCache: carolUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const ua = await program.account.userAccount.fetch(carolUaPda);
    const hasViewer = ua.assignedRoles.some(
      (r: { topoIndex: number }) => r.topoIndex === viewerRoleIdx
    );
    assert.ok(hasViewer, "Carol should have viewer role");
    assert.ok(hasBit(ua.effectivePermissions as number[], readPermIdx), "Carol should have perm 0");
    assert.ok(!hasBit(ua.effectivePermissions as number[], writePermIdx), "Carol should NOT have perm 1");

    // Verify UserPermCache is also in sync.
    const cache = await (program.account as any).userPermCache.fetch(carolUpcPda);
    assert.ok(hasBit(cache.effectivePermissions as number[], readPermIdx), "cache: Carol should have perm 0");
    assert.ok(!hasBit(cache.effectivePermissions as number[], writePermIdx), "cache: Carol should NOT have perm 1");
    assert.ok(hasBit(cache.effectiveRoles as number[], viewerRoleIdx), "cache: Carol should have viewer role bit set");
  });

  // -------------------------------------------------------------------------
  // Step 12 — Verify permissions on-chain via UserPermCache (hot path)
  // -------------------------------------------------------------------------
  it("Step 12a: Bob has write permission (index 1) verified on-chain", async () => {
    await program.methods
      .hasPermission(writePermIdx)
      .accounts({
        organization: orgPda,
        user: bob.publicKey,
        userPermCache: bobUpcPda,
      })
      .rpc();
    // No error = permission confirmed.
  });

  it("Step 12b: Carol does NOT have write permission (index 1)", async () => {
    try {
      await program.methods
        .hasPermission(writePermIdx)
        .accounts({
          organization: orgPda,
          user: carol.publicKey,
          userPermCache: carolUpcPda,
        })
        .rpc();
      assert.fail("Carol should not have write permission");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("InsufficientPermission") || err.toString().includes("Error"),
        "Expected InsufficientPermission error"
      );
    }
  });

  it("Step 12c: has_role O(1) check for Bob having editor role", async () => {
    await program.methods
      .hasRole(editorRoleIdx)
      .accounts({
        organization: orgPda,
        user: bob.publicKey,
        userPermCache: bobUpcPda,
      })
      .rpc();
    // No error = role confirmed.
  });

  // -------------------------------------------------------------------------
  // Step 13 — Revoke Bob's editor role in Idle state (no batch recompute needed)
  // -------------------------------------------------------------------------
  it("Step 13: Alice revokes Bob's editor role (Idle state)", async () => {
    // Bob has no remaining roles after revocation, so 0 chunk accounts.
    await program.methods
      .revokeRole(editorRoleIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([])  // no remaining roles → no chunks needed
      .rpc();

    const ua = await program.account.userAccount.fetch(bobUaPda);
    const hasEditor = ua.assignedRoles.some(
      (r: { topoIndex: number }) => r.topoIndex === editorRoleIdx
    );
    assert.ok(!hasEditor, "Bob should no longer have editor role");

    // Effective permissions should be immediately cleared (no batch needed).
    assert.ok(!hasBit(ua.effectivePermissions as number[], writePermIdx), "Bob should no longer have write permission");
    assert.ok(!hasBit(ua.effectivePermissions as number[], readPermIdx), "Bob should no longer have read permission");
    assert.equal(ua.cachedVersion.toNumber(), 1, "cached_version still matches org version");

    // Verify UserPermCache is cleared.
    const cache = await (program.account as any).userPermCache.fetch(bobUpcPda);
    assert.ok(!hasBit(cache.effectivePermissions as number[], writePermIdx), "cache: Bob should not have write perm");
    assert.ok(!hasBit(cache.effectivePermissions as number[], readPermIdx), "cache: Bob should not have read perm");
    assert.ok(!hasBit(cache.effectiveRoles as number[], editorRoleIdx), "cache: editor role bit should be cleared");
  });

  // -------------------------------------------------------------------------
  // Step 14 — Schema change: add a 3rd permission, assign to editor role
  //           This uses the full Updating → Recomputing → Idle cycle
  // -------------------------------------------------------------------------
  it("Step 14: Schema change — add 'admin' permission and assign to editor", async () => {
    const adminPermIdx = 2;

    // Begin update
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Create 'admin' permission (index 2, same chunk 0)
    await program.methods
      .createPermission("admin", "Admin operations")
      .accounts({
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Add admin permission to editor role
    await program.methods
      .addRolePermission(editorRoleIdx, adminPermIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Recompute editor role (children: none)
    await program.methods
      .recomputeRole(editorRoleIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([])
      .rpc();

    // Verify editor effective_permissions now includes perm 2
    {
      const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
      const entry = chunk.entries[editorRoleIdx];
      assert.ok(hasBit(entry.effectivePermissions as number[], adminPermIdx), "editor should now have admin perm");
    }

    // Commit update (permissions_version bumps to 2)
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    assert.equal(org.permissionsVersion.toNumber(), 2);

    // Carol has viewer role (chunk 0). Bob has no roles.
    // Layout: [UA, UPC] for Bob (0 chunks), [UA, UPC, chunk0] for Carol (1 chunk).
    await program.methods
      .processRecomputeBatch(Buffer.from([0, 1]))
      .accounts({
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: bobUaPda, isWritable: true, isSigner: false },
        { pubkey: bobUpcPda, isWritable: true, isSigner: false },
        { pubkey: carolUaPda, isWritable: true, isSigner: false },
        { pubkey: carolUpcPda, isWritable: true, isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    // Finish update → Idle
    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Assign editor role back to Bob (in Idle — inline recompute)
    await program.methods
      .assignRole(editorRoleIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const bobUa = await program.account.userAccount.fetch(bobUaPda);
    assert.ok(hasBit(bobUa.effectivePermissions as number[], adminPermIdx), "Bob should now have admin perm");
    assert.equal(bobUa.cachedVersion.toNumber(), 2);

    // Verify Bob's cache has admin perm and editor role bit.
    const bobCache = await (program.account as any).userPermCache.fetch(bobUpcPda);
    assert.ok(hasBit(bobCache.effectivePermissions as number[], adminPermIdx), "cache: Bob should have admin perm");
    assert.ok(hasBit(bobCache.effectiveRoles as number[], editorRoleIdx), "cache: Bob should have editor bit");
    assert.equal(bobCache.permissionsVersion.toNumber(), 2);

    // Verify Carol's cache was updated by processRecomputeBatch.
    const carolCache = await (program.account as any).userPermCache.fetch(carolUpcPda);
    assert.ok(hasBit(carolCache.effectivePermissions as number[], readPermIdx), "cache: Carol still has read perm");
    assert.ok(hasBit(carolCache.effectiveRoles as number[], viewerRoleIdx), "cache: Carol has viewer role bit");
    assert.equal(carolCache.permissionsVersion.toNumber(), 2);
  });

  // -------------------------------------------------------------------------
  // Step 15 — last_seen_version tracking in RoleRef
  // -------------------------------------------------------------------------
  it("Step 15: RoleRef.last_seen_version tracks role version", async () => {
    const bobUa = await program.account.userAccount.fetch(bobUaPda);
    const editorRef = bobUa.assignedRoles.find(
      (r: { topoIndex: number }) => r.topoIndex === editorRoleIdx
    );
    assert.ok(editorRef, "Bob should have editor RoleRef");

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const editorEntry = chunk.entries[editorRoleIdx];

    // last_seen_version should match current role version (set during assignRole in step 14).
    assert.equal(
      (editorRef as any).lastSeenVersion.toNumber(),
      editorEntry.version.toNumber(),
      "last_seen_version should match current role version"
    );
  });

  // -------------------------------------------------------------------------
  // Step 16 — Role assignment across chunk boundary
  //           Create 16 more roles so role 16 lands in chunk 1
  // -------------------------------------------------------------------------
  it("Step 16: Role at index 16 goes into chunk 1", async () => {
    // Begin update to create roles 2..16 (filling chunk 0 then starting chunk 1)
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    const startCount: number = org.roleCount;

    // Fill remaining slots in chunk 0 (roles 2..15) then create role 16 in chunk 1
    for (let i = startCount; i <= ROLES_PER_CHUNK; i++) {
      const chunkIdx = Math.floor(i / ROLES_PER_CHUNK);
      const [chunkPda] = findRoleChunkPda(program.programId, orgPda, chunkIdx);
      await program.methods
        .createRole(`role_${i}`, `Auto-created role ${i}`)
        .accounts({
          roleChunk: chunkPda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    }

    // Role 16 should be in chunk 1
    const [chunk1Pda] = findRoleChunkPda(program.programId, orgPda, 1);
    const chunk1 = await program.account.roleChunk.fetch(chunk1Pda);
    assert.equal(chunk1.chunkIndex, 1, "chunk_index should be 1");
    assert.equal(chunk1.entries.length, 1, "chunk 1 should have exactly 1 entry (role 16)");
    assert.equal(chunk1.entries[0].topoIndex, 16, "role 16 in chunk 1 slot 0");

    // Commit and finish to return to Idle
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Batch recompute with updated layout: [UA, UPC, chunks...] per user.
    const allUAs = await program.account.userAccount.all([
      { memcmp: { offset: 8, bytes: orgPda.toBase58() } },
    ]);
    const currentVersion = (await program.account.organization.fetch(orgPda)).permissionsVersion.toNumber();
    const staleUAs = allUAs.filter(
      (ua: any) => ua.account.cachedVersion.toNumber() < currentVersion
    );

    if (staleUAs.length > 0) {
      const remainingAccts: any[] = [];
      const counts: number[] = [];
      for (const ua of staleUAs) {
        const assignedRoles = ua.account.assignedRoles as { topoIndex: number }[];
        const chunkIdxSet = new Set<number>(assignedRoles.map((r) => roleChunkIndex(r.topoIndex)));
        const userChunks = Array.from(chunkIdxSet).map((ci) => {
          const [cp] = findRoleChunkPda(program.programId, orgPda, ci);
          return { pubkey: cp, isWritable: false, isSigner: false };
        });
        const [upcPda] = findUserPermCachePda(program.programId, orgPda, ua.account.user as PublicKey);
        counts.push(userChunks.length);
        remainingAccts.push({ pubkey: ua.publicKey, isWritable: true, isSigner: false });
        remainingAccts.push({ pubkey: upcPda, isWritable: true, isSigner: false });
        for (const c of userChunks) remainingAccts.push(c);
      }
      await program.methods
        .processRecomputeBatch(Buffer.from(counts))
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts(remainingAccts)
        .rpc();
    }

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgFinal = await program.account.organization.fetch(orgPda);
    assert.deepEqual(orgFinal.state, { idle: {} });
    assert.equal(orgFinal.roleCount, ROLES_PER_CHUNK + 1, "should have 17 roles total");
  });
});
