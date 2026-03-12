import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorError } from "@coral-xyz/anchor";
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

function findOrgPda(programId: PublicKey, admin: PublicKey, name: string): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("organization"), admin.toBuffer(), Buffer.from(name)],
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

  // ---------------------------------------------------------------------------
  // Helper: recompute every active role in `targetOrgPda`.
  // recompute_role unconditionally calls find_perm_chunk_in_accounts for every
  // set bit in direct_permissions, so roles that have any direct permissions
  // require pcc=1 with the relevant PermChunk. Roles with no direct_permissions
  // can use pcc=0 (empty remaining_accounts).
  // All perms in this suite live in chunk 0, so permChunk0Pda is always correct.
  // Required before every commitUpdate now that the on-chain handler enforces
  // roles_pending_recompute == 0.
  // ---------------------------------------------------------------------------
  async function recomputeAllRoles(targetOrgPda: PublicKey): Promise<void> {
    const org = await program.account.organization.fetch(targetOrgPda);
    const roleCount = org.roleCount as number;
    if (roleCount === 0) return;
    const currentVersion = org.permissionsVersion as anchor.BN;
    const numChunks = Math.ceil(roleCount / ROLES_PER_CHUNK);
    for (let ci = 0; ci < numChunks; ci++) {
      const [chunkPda] = findRoleChunkPda(program.programId, targetOrgPda, ci);
      const chunk = await (program.account as any).roleChunk.fetch(chunkPda);
      for (const entry of chunk.entries) {
        if (!entry.active) continue;
        // Skip roles already recomputed this cycle — makes the helper idempotent
        // so it can be called multiple times within a single update cycle without
        // hitting the AlreadyRecomputed guard.
        if ((entry.recomputeEpoch as anchor.BN).eq(currentVersion)) continue;

        const hasDirectPerms = (entry.directPermissions as number[]).some((b: number) => b !== 0);
        const pcc = hasDirectPerms ? 1 : 0;

        // Collect unique cross-chunk child RoleChunk PDAs (children whose chunk
        // index differs from the role being recomputed need to be in remaining_accounts).
        const children = entry.children as number[];
        const crossChunkIdxSet = new Set<number>(
          children
            .map((c: number) => Math.floor(c / ROLES_PER_CHUNK))
            .filter((childCi: number) => childCi !== ci)
        );
        const childChunkAccts = Array.from(crossChunkIdxSet).map((childCi: number) => {
          const [cp] = findRoleChunkPda(program.programId, targetOrgPda, childCi);
          return { pubkey: cp, isWritable: false, isSigner: false };
        });

        const remainingAccts = [
          ...(hasDirectPerms ? [{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }] : []),
          ...childChunkAccts,
        ];

        await program.methods
          .recomputeRole(entry.topoIndex as number, pcc)
          .accounts({
            roleChunk: chunkPda,
            organization: targetOrgPda,
            authority: alice.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(remainingAccts)
          .rpc();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 1 — Alice creates organisation (starts in Idle)
  // -------------------------------------------------------------------------
  it("Step 1: Alice creates organisation 'acme_corp'", async () => {
    [orgPda] = findOrgPda(program.programId, alice.publicKey, orgName);

    await program.methods
      .initializeOrganization(orgName, 3)
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
        permChunk: permChunk0Pda,  // active check: verify permission is not soft-deleted
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
        permChunk: permChunk0Pda,  // active check: verify permission is not soft-deleted
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .addRolePermission(editorRoleIdx, writePermIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        permChunk: permChunk0Pda,  // active check: verify permission is not soft-deleted
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
      .recomputeRole(viewerRoleIdx, 1)  // perm_chunk_count=1: permChunk0 filters direct perms
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    const chunk = await program.account.roleChunk.fetch(roleChunk0Pda);
    const entry = chunk.entries[viewerRoleIdx];
    assert.ok(hasBit(entry.effectivePermissions as number[], readPermIdx), "viewer effective should have perm 0");
    assert.ok(!hasBit(entry.effectivePermissions as number[], writePermIdx), "viewer effective should NOT have perm 1");
  });

  it("Step 7b: recompute editor role", async () => {
    await program.methods
      .recomputeRole(editorRoleIdx, 1)  // perm_chunk_count=1: permChunk0 filters direct perms
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      ])
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
    // Layout: [permChunk0], [UA, UPC] per user (no role chunks). perm_chunk_count=1 required when org has permissions.
    const remainingAccounts = [
      { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      { pubkey: bobUaPda, isWritable: true, isSigner: false },
      { pubkey: bobUpcPda, isWritable: true, isSigner: false },
      { pubkey: carolUaPda, isWritable: true, isSigner: false },
      { pubkey: carolUpcPda, isWritable: true, isSigner: false },
    ];

    await program.methods
      .processRecomputeBatch(Buffer.from([0, 0]), 1)
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
      .assignRole(editorRoleIdx, 0)  // perm_chunk_count=0: trust cached effective_perms
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
      .assignRole(viewerRoleIdx, 0)  // perm_chunk_count=0: trust cached effective_perms
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
    // Bob has no remaining roles after revocation and no direct permissions.
    // perm_chunk_count=1 required when org has permissions; no role chunks needed.
    await program.methods
      .revokeRole(editorRoleIdx, 1)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }])
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
        permChunk: permChunk0Pda,  // active check: verify permission is not soft-deleted
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Recompute editor role (children: none). perm_chunk_count=1 → permChunk0 filters active perms.
    await program.methods
      .recomputeRole(editorRoleIdx, 1)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    // Recompute viewer role (unchanged, but all active roles must be recomputed
    // before commitUpdate now that roles_pending_recompute is enforced).
    await program.methods
      .recomputeRole(viewerRoleIdx, 1)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      ])
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
    // Layout: [permChunk0], [UA, UPC] for Bob (0 role chunks), [UA, UPC, roleChunk0] for Carol (1 chunk).
    await program.methods
      .processRecomputeBatch(Buffer.from([0, 1]), 1)
      .accounts({
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
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
    // pcc=1 filters role's effective_permissions through permChunk0 (drops inactive bits).
    await program.methods
      .assignRole(editorRoleIdx, 1)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
      ])
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
  // NOTE: Step 16 processRecomputeBatch is fixed above (perm_chunk_count=0).
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

    // Recompute all active roles (roles_pending_recompute must be 0 at commitUpdate).
    await recomputeAllRoles(orgPda);

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
      const remainingAccts: any[] = [{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }];
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
        .processRecomputeBatch(Buffer.from(counts), 1)
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

  // ---------------------------------------------------------------------------
  // Security: Cross-organization privilege escalation in delegation
  //
  // The delegation path in assign_role / revoke_role reads a UserPermCache from
  // remaining_accounts[0]. Before the fix, only `user == authority` was checked —
  // the `organization` field was never verified. This allowed an attacker holding
  // MANAGE_ROLES in org A to call assign_role / revoke_role in org B by passing
  // their org-A cache.
  //
  // Fix: require(caller_cache.organization == org_key) was added to both handlers.
  //
  // Tests:
  //   1. Attack blocked (assign_role)  — cross-org cache → NotSuperAdmin
  //   2. Attack blocked (revoke_role)  — cross-org cache → NotSuperAdmin
  //   3. Legitimate delegation (assign_role) — correct-org cache → success
  // ---------------------------------------------------------------------------

  // MANAGE_ROLES_PERMISSION_INDEX is a well-known constant in state.rs.
  const MANAGE_ROLES_PERM_IDX = 3;

  // A fresh org that carol's attack cache belongs to.
  const attackOrgName = "attack_org";
  let attackOrgPda: PublicKey;
  let carolUaAttackOrgPda: PublicKey;
  let carolUpcAttackOrgPda: PublicKey;

  // A victim user created in acme_corp for delegation tests.
  const dave = Keypair.generate();
  let daveUaPda: PublicKey;
  let daveUpcPda: PublicKey;

  before(async () => {
    const sig = await provider.connection.requestAirdrop(dave.publicKey, 2 * LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(sig);
  });

  it("Security setup: create attack_org and carol's user account in it", async () => {
    [attackOrgPda] = findOrgPda(program.programId, alice.publicKey, attackOrgName);
    [carolUaAttackOrgPda] = findUserAccountPda(program.programId, attackOrgPda, carol.publicKey);
    [carolUpcAttackOrgPda] = findUserPermCachePda(program.programId, attackOrgPda, carol.publicKey);

    // Alice creates attack_org (she's the super_admin; carol will be a member).
    await program.methods
      .initializeOrganization(attackOrgName, 3)
      .accounts({
        organization: attackOrgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Create carol's user account in attack_org so her UPC exists on-chain.
    await program.methods
      .createUserAccount()
      .accounts({
        userAccount: carolUaAttackOrgPda,
        userPermCache: carolUpcAttackOrgPda,
        organization: attackOrgPda,
        user: carol.publicKey,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Give carol MANAGE_ROLES (index 3) in attack_org through a full update cycle so
    // her attack_org cache has the permission bit set and a current version.
    // update cycle: begin → create perms 0-3 → commit → empty batch → finish
    await program.methods
      .beginUpdate()
      .accounts({ organization: attackOrgPda, authority: alice.publicKey })
      .rpc();

    const [attackPermChunk0Pda] = findPermChunkPda(program.programId, attackOrgPda, 0);
    for (const [name, desc] of [
      ["perm_0", "placeholder 0"],
      ["perm_1", "placeholder 1"],
      ["perm_2", "placeholder 2"],
      ["manage_roles", "Allows managing role assignments"],
    ]) {
      await program.methods
        .createPermission(name, desc)
        .accounts({
          permChunk: attackPermChunk0Pda,
          organization: attackOrgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    }

    await program.methods
      .commitUpdate()
      .accounts({ organization: attackOrgPda, authority: alice.publicKey })
      .rpc();

    // Process all members (carol, no roles → 0 chunks) so users_pending_recompute reaches 0.
    await program.methods
      .processRecomputeBatch(Buffer.from([0]), 1)
      .accounts({ organization: attackOrgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: attackPermChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaAttackOrgPda,  isWritable: true, isSigner: false },
        { pubkey: carolUpcAttackOrgPda, isWritable: true, isSigner: false },
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: attackOrgPda, authority: alice.publicKey })
      .rpc();

    // In Idle: assign MANAGE_ROLES directly to carol in attack_org.
    // Pass permChunk so the handler can verify the permission is active.
    await program.methods
      .assignUserPermission(MANAGE_ROLES_PERM_IDX)
      .accounts({
        userAccount: carolUaAttackOrgPda,
        userPermCache: carolUpcAttackOrgPda,
        permChunk: attackPermChunk0Pda,
        organization: attackOrgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const carolAttackCache = await (program.account as any).userPermCache.fetch(carolUpcAttackOrgPda);
    assert.ok(
      hasBit(carolAttackCache.effectivePermissions as number[], MANAGE_ROLES_PERM_IDX),
      "carol should have MANAGE_ROLES in attack_org cache"
    );
  });

  it("Security setup: create dave's user account in acme_corp", async () => {
    [daveUaPda] = findUserAccountPda(program.programId, orgPda, dave.publicKey);
    [daveUpcPda] = findUserPermCachePda(program.programId, orgPda, dave.publicKey);

    await program.methods
      .createUserAccount()
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        organization: orgPda,
        user: dave.publicKey,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });

  // ── Attack test 1: assign_role ─────────────────────────────────────────────

  it("cross-org assign_role: supplying a cache from a different org is rejected with NotSuperAdmin", async () => {
    // carol has MANAGE_ROLES in attack_org (confirmed above).
    // She tries to use her attack_org UPC as delegation proof for acme_corp.
    // Without the fix this would succeed; with the fix it must fail.
    try {
      await program.methods
        .assignRole(viewerRoleIdx, 0)  // pcc=0 for this attack attempt
        .accounts({
          userAccount: daveUaPda,
          userPermCache: daveUpcPda,
          roleChunk: roleChunk0Pda,
          organization: orgPda,        // target: acme_corp
          authority: carol.publicKey,  // carol signs (user check passes)
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([
          // Attack: pass carol's cache from a different org
          { pubkey: carolUpcAttackOrgPda, isWritable: false, isSigner: false },
        ])
        .signers([carol])
        .rpc();
      assert.fail("Expected NotSuperAdmin — cross-org cache must be rejected");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("NotSuperAdmin"),
        `Expected NotSuperAdmin, got: ${err}`
      );
    }

    // dave must still have no roles
    const daveUa = await program.account.userAccount.fetch(daveUaPda);
    assert.equal(daveUa.assignedRoles.length, 0, "dave should have no roles — assign was blocked");
  });

  // ── Attack test 2: revoke_role ─────────────────────────────────────────────

  it("cross-org revoke_role: supplying a cache from a different org is rejected with NotSuperAdmin", async () => {
    // Alice (super_admin) first assigns the viewer role to dave legitimately.
    await program.methods
      .assignRole(viewerRoleIdx, 0)  // pcc=0: trust cached effective_perms
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    {
      const ua = await program.account.userAccount.fetch(daveUaPda);
      assert.ok(
        ua.assignedRoles.some((r: any) => r.topoIndex === viewerRoleIdx),
        "dave should have viewer role before revoke attempt"
      );
    }

    // carol tries to revoke dave's viewer role using her attack_org cache.
    try {
      await program.methods
        .revokeRole(viewerRoleIdx, 1)
        .accounts({
          userAccount: daveUaPda,
          userPermCache: daveUpcPda,
          roleChunk: roleChunk0Pda,
          organization: orgPda,        // target: acme_corp
          authority: carol.publicKey,  // carol signs
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([
          // Attack: cross-org cache as delegation proof; permChunk0 for acme_corp to pass PermChunksRequired
          { pubkey: carolUpcAttackOrgPda, isWritable: false, isSigner: false },
          { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        ])
        .signers([carol])
        .rpc();
      assert.fail("Expected NotSuperAdmin — cross-org cache must be rejected");
    } catch (err: any) {
      assert.ok(
        err.toString().includes("NotSuperAdmin"),
        `Expected NotSuperAdmin, got: ${err}`
      );
    }

    // dave must still have the viewer role (revoke was blocked)
    const daveUa = await program.account.userAccount.fetch(daveUaPda);
    assert.ok(
      daveUa.assignedRoles.some((r: any) => r.topoIndex === viewerRoleIdx),
      "dave should still have viewer role — revoke was blocked"
    );
  });

  // ── Positive test: legitimate delegation must still work ───────────────────

  it("delegation with correct-org cache is accepted", async () => {
    // Give carol MANAGE_ROLES in acme_corp itself so she has a valid delegation cache.
    // acme_corp currently has next_permission_index = 3; MANAGE_ROLES_PERM_IDX = 3.
    // Run a minimal update cycle to create perm 3 ("manage_roles") in acme_corp.
    // On any failure (e.g. ProgramAccountNotFound), ensure we leave org Idle so later tests don't see OrgNotIdle.
    try {
      await program.methods
        .beginUpdate()
        .accounts({ organization: orgPda, authority: alice.publicKey })
        .rpc();

      await program.methods
        .createPermission("manage_roles", "Allows managing role assignments")
        .accounts({
          permChunk: permChunk0Pda,   // perm index 3 lands in chunk 0 (indices 0-31)
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // Recompute all active roles (roles_pending_recompute must be 0 at commitUpdate).
      await recomputeAllRoles(orgPda);

      await program.methods
        .commitUpdate()
        .accounts({ organization: orgPda, authority: alice.publicKey })
        .rpc();

      // Process ALL members (Bob=editor/chunk0, Carol=viewer/chunk0, Dave=viewer/chunk0).
      await program.methods
        .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts([
          { pubkey: permChunk0Pda,  isWritable: false, isSigner: false },
          { pubkey: bobUaPda,       isWritable: true,  isSigner: false },
          { pubkey: bobUpcPda,      isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false },
          { pubkey: carolUaPda,     isWritable: true,  isSigner: false },
          { pubkey: carolUpcPda,    isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false },
          { pubkey: daveUaPda,      isWritable: true,  isSigner: false },
          { pubkey: daveUpcPda,     isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false },
        ])
        .rpc();

      await program.methods
        .finishUpdate()
        .accounts({ organization: orgPda, authority: alice.publicKey })
        .rpc();

      // In Idle: grant carol MANAGE_ROLES (index 3) directly in acme_corp.
    // Pass permChunk so the handler verifies the permission is active.
    await program.methods
      .assignUserPermission(MANAGE_ROLES_PERM_IDX)
      .accounts({
        userAccount: carolUaPda,
        userPermCache: carolUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const carolAcmeCache = await (program.account as any).userPermCache.fetch(carolUpcPda);
    assert.ok(
      hasBit(carolAcmeCache.effectivePermissions as number[], MANAGE_ROLES_PERM_IDX),
      "carol should have MANAGE_ROLES in acme_corp cache"
    );

    // Clean up: revoke dave's viewer role so we can re-assign it via delegation.
    await program.methods
      .revokeRole(viewerRoleIdx, 1)
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }])
      .rpc();

    // Now carol (delegated) assigns the viewer role to dave using her acme_corp cache.
    await program.methods
      .assignRole(viewerRoleIdx, 0)  // pcc=0: trust cached effective_perms
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,        // acme_corp
        authority: carol.publicKey,  // carol signs as delegated caller
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        // Legitimate: carol's own acme_corp cache as delegation proof
        { pubkey: carolUpcPda, isWritable: false, isSigner: false },
      ])
      .signers([carol])
      .rpc();

    const daveUa = await program.account.userAccount.fetch(daveUaPda);
    assert.ok(
      daveUa.assignedRoles.some((r: any) => r.topoIndex === viewerRoleIdx),
      "dave should have viewer role — assigned via carol's legitimate delegation"
    );

    const daveCache = await (program.account as any).userPermCache.fetch(daveUpcPda);
    assert.ok(
      hasBit(daveCache.effectiveRoles as number[], viewerRoleIdx),
      "dave's cache should have viewer role bit set"
    );
    assert.ok(
      hasBit(daveCache.effectivePermissions as number[], readPermIdx),
      "dave should have read permission from viewer role"
    );
    } finally {
      // If the test failed partway (e.g. ProgramAccountNotFound), org may be Updating or Recomputing.
      // Complete the cycle so later tests see Idle.
      const org = await program.account.organization.fetch(orgPda);
      const state = (org.state as any);
      if (state.updating !== undefined) {
        await recomputeAllRoles(orgPda);
        await program.methods.commitUpdate().accounts({ organization: orgPda, authority: alice.publicKey }).rpc();
        await completeRecomputeCycle(1);
      } else if (state.recomputing !== undefined) {
        await completeRecomputeCycle(1);
      }
    }
  });

  // ---------------------------------------------------------------------------
  // Security: revoke_role / revoke_user_permission resurrect soft-deleted
  //           permissions from stale direct_permissions bits
  //
  // Before the fix, both handlers started the recompute from
  // `ua.direct_permissions.clone()` directly. After a permission is
  // soft-deleted and processRecomputeBatch has run, direct_permissions still
  // retains the stale bit (only effective_permissions is cleaned). A subsequent
  // revokeRole or revokeUserPermission call would then copy that stale bit into
  // effective_permissions, effectively resurrecting the deleted permission.
  //
  // Fix: both handlers accept perm_chunk_count: u8 and split remaining_accounts
  // into [perm_chunks (0..pcc), role_chunks (pcc..)]. direct_permissions bits
  // are filtered through the supplied PermChunks — inactive bits are dropped.
  //
  // Tests:
  //   Setup: create temp_perm (index 4), assign it to dave, soft-delete it,
  //          run processRecomputeBatch → dave.direct_permissions has stale bit 4
  //          but dave.effective_permissions does NOT.
  //   A. revokeRole:            stale bit 4 is NOT resurrected
  //   B. revokeUserPermission:  stale bit 4 is NOT resurrected
  // ---------------------------------------------------------------------------

  let tempPermIdx: number; // will be 4 (nextPermissionIndex after delegation tests)

  it("stale-bit setup: create temp_perm, assign to dave, soft-delete it", async () => {
    // Phase 1: create temp_perm (next index in acme_corp after the chunk-index cycle).
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await program.methods
      .createPermission("temp_perm", "Temporary permission for stale-bit test")
      .accounts({
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // All active roles must be recomputed before commitUpdate.
    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Process all 3 members (Bob, Carol, Dave). Each has 1 role chunk (roleChunk0).
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    tempPermIdx = (org.nextPermissionIndex as number) - 1;

    // Phase 2: assign temp_perm to dave directly (Idle state).
    await program.methods
      .assignUserPermission(tempPermIdx)
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    {
      const ua = await program.account.userAccount.fetch(daveUaPda);
      assert.ok(
        hasBit(ua.directPermissions as number[], tempPermIdx),
        "dave should have temp_perm in direct_permissions"
      );
      assert.ok(
        hasBit(ua.effectivePermissions as number[], tempPermIdx),
        "dave should have temp_perm in effective_permissions"
      );
    }

    // Phase 3: soft-delete temp_perm and run processRecomputeBatch for dave.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await program.methods
      .deletePermission(tempPermIdx)
      .accounts({
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .rpc();

    // Recompute all active roles (temp_perm was deleted; roles that had it will
    // have the bit filtered out by recompute_role's PermChunk validation).
    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Process all 3 members (Bob, Carol, Dave): perm_chunk_count=1 so the handler
    // filters stale direct_permissions bits through permChunk0.
    // Each user has 1 role chunk (roleChunk0). users_pending_recompute must reach 0.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda,  isWritable: false, isSigner: false }, // perm chunk (pcc=1)
        { pubkey: bobUaPda,       isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,      isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false },
        { pubkey: carolUaPda,     isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false },
        { pubkey: daveUaPda,      isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda,  isWritable: false, isSigner: false }, // viewer in chunk 0
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Verify the expected stale state: direct_permissions still has bit tempPermIdx
    // but effective_permissions does NOT (it was filtered out by processRecomputeBatch).
    const ua = await program.account.userAccount.fetch(daveUaPda);
    assert.ok(
      hasBit(ua.directPermissions as number[], tempPermIdx),
      "stale bit should remain in direct_permissions (processRecomputeBatch never clears it)"
    );
    assert.ok(
      !hasBit(ua.effectivePermissions as number[], tempPermIdx),
      "stale bit should NOT be in effective_permissions after processRecomputeBatch"
    );
    assert.ok(
      hasBit(ua.effectivePermissions as number[], readPermIdx),
      "dave should still have read from viewer role"
    );
  });

  it("revokeRole with perm_chunk_count>0 does not resurrect stale direct_permissions bits", async () => {
    // dave has: viewer role (0), stale bit tempPermIdx in direct_permissions.
    // Revoke the viewer role, supplying permChunk0 so the handler can filter
    // the stale bit. dave has no remaining roles → no role chunks needed.
    await program.methods
      .revokeRole(viewerRoleIdx, 1)  // perm_chunk_count=1
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false }, // perm chunk (pcc=1)
        // no role chunk accounts — dave has no remaining roles
      ])
      .rpc();

    const ua = await program.account.userAccount.fetch(daveUaPda);

    // Viewer role should be gone.
    assert.equal(ua.assignedRoles.length, 0, "dave should have no roles after revokeRole");

    // Stale bit must NOT appear in effective_permissions.
    assert.ok(
      !hasBit(ua.effectivePermissions as number[], tempPermIdx),
      "stale direct_permissions bit must NOT be resurrected in effective_permissions after revokeRole"
    );

    // Read perm (came from viewer role) should also be gone.
    assert.ok(
      !hasBit(ua.effectivePermissions as number[], readPermIdx),
      "read perm should be gone (viewer role was revoked)"
    );

    // Verify cache is also clean.
    const cache = await (program.account as any).userPermCache.fetch(daveUpcPda);
    assert.ok(
      !hasBit(cache.effectivePermissions as number[], tempPermIdx),
      "cache: stale bit must NOT be resurrected"
    );
    assert.ok(
      !hasBit(cache.effectiveRoles as number[], viewerRoleIdx),
      "cache: viewer role bit should be cleared"
    );
  });

  it("revokeUserPermission with perm_chunk_count>0 does not resurrect stale direct_permissions bits", async () => {
    // Setup: re-assign viewer role to dave and give him an active direct perm (read/0).
    // After this, dave has:
    //   assignedRoles:      [viewer (0)]
    //   directPermissions:  stale bit tempPermIdx + active bit readPermIdx
    //   effectivePermissions: bit readPermIdx (viewer already provides it)

    await program.methods
      .assignRole(viewerRoleIdx, 0)
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .assignUserPermission(readPermIdx)
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    {
      const ua = await program.account.userAccount.fetch(daveUaPda);
      assert.ok(hasBit(ua.directPermissions as number[], readPermIdx), "dave should have read in direct_permissions");
      assert.ok(hasBit(ua.directPermissions as number[], tempPermIdx), "stale bit should still be in direct_permissions");
    }

    // Revoke read perm (0) from dave.
    // remaining_accounts layout: [permChunk0 (pcc=1), roleChunk0 (remaining roles)]
    await program.methods
      .revokeUserPermission(readPermIdx, 1)  // perm_chunk_count=1
      .accounts({
        userAccount: daveUaPda,
        userPermCache: daveUpcPda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false }, // perm chunk (pcc=1)
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false }, // viewer role chunk
      ])
      .rpc();

    const ua = await program.account.userAccount.fetch(daveUaPda);

    // Stale bit must NOT appear in effective_permissions.
    assert.ok(
      !hasBit(ua.effectivePermissions as number[], tempPermIdx),
      "stale direct_permissions bit must NOT be resurrected in effective_permissions after revokeUserPermission"
    );

    // Read perm should still be in effective_permissions — it comes from the
    // viewer role, not from the revoked direct assignment.
    assert.ok(
      hasBit(ua.effectivePermissions as number[], readPermIdx),
      "read perm should still be in effective_permissions (contributed by viewer role)"
    );

    // The revoked bit should be cleared from direct_permissions.
    assert.ok(
      !hasBit(ua.directPermissions as number[], readPermIdx),
      "read bit should be cleared from direct_permissions after revokeUserPermission"
    );

    // Stale bit remains in direct_permissions (by design — only processRecomputeBatch cleans it).
    assert.ok(
      hasBit(ua.directPermissions as number[], tempPermIdx),
      "stale bit remains in direct_permissions (cleanup is deferred to processRecomputeBatch)"
    );

    // Verify cache.
    const cache = await (program.account as any).userPermCache.fetch(daveUpcPda);
    assert.ok(
      !hasBit(cache.effectivePermissions as number[], tempPermIdx),
      "cache: stale bit must NOT appear in effective_permissions"
    );
    assert.ok(
      hasBit(cache.effectivePermissions as number[], readPermIdx),
      "cache: read perm should be present (from viewer role)"
    );
  });

  // ---------------------------------------------------------------------------
  // Helper: process all three acme_corp members (Bob/Carol/Dave, each in chunk 0)
  // and finish the update cycle. Used by the issue-fix integration tests below.
  // ---------------------------------------------------------------------------
  async function completeRecomputeCycle(pcc: number = 1): Promise<void> {
    const extraAccounts: anchor.web3.AccountMeta[] = [];
    if (pcc > 0) {
      extraAccounts.push({ pubkey: permChunk0Pda, isWritable: false, isSigner: false });
    }
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), pcc)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        ...extraAccounts,
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();
    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
  }

  // ---------------------------------------------------------------------------
  // Integration test: assignUserPermission must reject soft-deleted permissions.
  // ---------------------------------------------------------------------------
  it("assignUserPermission with deleted permission is rejected with PermissionInactive", async () => {
    // tempPermIdx (4) was soft-deleted in the stale-bit setup test.
    // Trying to assign it directly must fail regardless of the caller's authority.
    try {
      await program.methods
        .assignUserPermission(tempPermIdx)
        .accounts({
          userAccount: daveUaPda,
          userPermCache: daveUpcPda,
          permChunk: permChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("expected PermissionInactive");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "PermissionInactive");
    }
  });

  // ---------------------------------------------------------------------------
  // Integration test: add_role_permission must reject soft-deleted permissions.
  // ---------------------------------------------------------------------------
  it("add_role_permission with deleted permission is rejected with PermissionInactive", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    try {
      await program.methods
        .addRolePermission(viewerRoleIdx, tempPermIdx)
        .accounts({
          roleChunk: roleChunk0Pda,
          permChunk: permChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("expected PermissionInactive");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "PermissionInactive");
    }

    // No structural change to roles — recompute all then commit.
    await recomputeAllRoles(orgPda);
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
    await completeRecomputeCycle(1);
  });

  // ---------------------------------------------------------------------------
  // Integration test: finishUpdate must reject when users_pending_recompute > 0.
  // ---------------------------------------------------------------------------
  it("finishUpdate before all users are processed is rejected with UpdateIncomplete", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Org is now Recomputing with users_pending_recompute = 3 (Bob, Carol, Dave).
    // Calling finishUpdate immediately must be rejected.
    try {
      await program.methods
        .finishUpdate()
        .accounts({ organization: orgPda, authority: alice.publicKey })
        .rpc();
      assert.fail("expected UpdateIncomplete");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "UpdateIncomplete");
    }

    // Process all users and finish cleanly.
    await completeRecomputeCycle(1);
  });

  // ---------------------------------------------------------------------------
  // Integration test: has_permission and has_role must reject stale caches.
  // A cache is stale when its permissions_version < org.permissions_version.
  // ---------------------------------------------------------------------------
  it("has_permission and has_role reject stale user cache with StalePermissions", async () => {
    // Bump permissions_version by committing a no-op update cycle.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Dave's cache now lags behind org.permissions_version by 1.
    // Both verification instructions must reject with StalePermissions.
    try {
      await program.methods
        .hasPermission(readPermIdx)
        .accounts({ organization: orgPda, user: dave.publicKey, userPermCache: daveUpcPda })
        .rpc();
      assert.fail("expected StalePermissions");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "StalePermissions");
    }

    try {
      await program.methods
        .hasRole(viewerRoleIdx)
        .accounts({ organization: orgPda, user: dave.publicKey, userPermCache: daveUpcPda })
        .rpc();
      assert.fail("expected StalePermissions");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "StalePermissions");
    }

    // Bring all caches up to date, then verify both instructions succeed.
    await completeRecomputeCycle(1);

    await program.methods
      .hasPermission(readPermIdx)
      .accounts({ organization: orgPda, user: dave.publicKey, userPermCache: daveUpcPda })
      .rpc();

    await program.methods
      .hasRole(viewerRoleIdx)
      .accounts({ organization: orgPda, user: dave.publicKey, userPermCache: daveUpcPda })
      .rpc();
  });

  // ---------------------------------------------------------------------------
  // Test: processRecomputeBatch rejects duplicate users
  //
  // Before the fix, duplicate detection used Vec::contains which is O(n²) per
  // batch.  After the fix, BTreeSet::insert is used — O(n log n) — and the
  // boolean return value directly signals a duplicate without a separate
  // contains() call.  Functional behaviour is unchanged: duplicates must be
  // rejected so that a single member cannot decrement users_pending_recompute
  // more than once.
  // ---------------------------------------------------------------------------
  it("processRecomputeBatch rejects duplicate user accounts with AccountCountMismatch", async () => {
    // Advance to Recomputing state so processRecomputeBatch is callable.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Submit Bob's UA twice in the same batch — must be rejected.
    try {
      await program.methods
        .processRecomputeBatch(Buffer.from([1, 1]), 1)
        .accounts({
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([
          { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
          { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
          { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
          // Bob appears a second time — must trigger AccountCountMismatch.
          { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
          { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        ])
        .rpc();
      assert.fail("expected AccountCountMismatch for duplicate user");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "AccountCountMismatch",
        `Expected AccountCountMismatch, got: ${err}`
      );
    }

    // Org is still Recomputing — complete it cleanly before the next test.
    await completeRecomputeCycle(1);
  });

  // ---------------------------------------------------------------------------
  // Test: has_permission rejects permission_index >= 256 with InvalidPermissionIndex
  //
  // UserPermCache uses a fixed 32-byte bitmask (256 bits).  A permission with
  // index >= 256 can never be stored in the cache, so verification must be
  // rejected at the boundary.  This also validates why create_permission now
  // caps next_permission_index at 255: creating index 256 would produce a
  // permission that is permanently unverifiable.
  // ---------------------------------------------------------------------------
  it("has_permission rejects permission_index >= 256 with InvalidPermissionIndex", async () => {
    try {
      await program.methods
        .hasPermission(256)
        .accounts({
          organization: orgPda,
          user: dave.publicKey,
          userPermCache: daveUpcPda,
        })
        .rpc();
      assert.fail("expected InvalidPermissionIndex");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "InvalidPermissionIndex"
      );
    }

    // Exact boundary: index 255 should NOT throw InvalidPermissionIndex
    // (the bit simply won't be set, so InsufficientPermission is returned instead).
    try {
      await program.methods
        .hasPermission(255)
        .accounts({
          organization: orgPda,
          user: dave.publicKey,
          userPermCache: daveUpcPda,
        })
        .rpc();
      assert.fail("expected InsufficientPermission for unset bit at index 255");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "InsufficientPermission",
        "index 255 is in-range; expect InsufficientPermission not InvalidPermissionIndex"
      );
    }
  });

  // ---------------------------------------------------------------------------
  // Test: processRecomputeBatch must clear effective_roles for soft-deleted roles
  //
  // Before the fix, effective_roles was populated directly from ua.assigned_roles
  // without checking entry.active. After a role is soft-deleted globally and the
  // recompute cycle runs, users who still have that role in their UA's
  // assigned_roles would continue to have its bit set in effective_roles —
  // causing has_role to incorrectly return success for a deleted role.
  //
  // Fix: active_role_indices is collected inside the `if entry.active { }` block,
  // so only live roles contribute to the effective_roles bitmask.
  //
  // Test flow:
  //   1. Verify Dave currently has viewer role bit set (pre-condition).
  //   2. Delete viewer role (soft-delete) in an update cycle.
  //   3. Run processRecomputeBatch for all users.
  //   4. After the cycle Dave's effective_roles must NOT include viewer role.
  //   5. has_role(viewerRoleIdx) for Dave must return RoleNotAssigned.
  //   6. effective_permissions must not include read perm (from viewer role).
  // ---------------------------------------------------------------------------
  it("processRecomputeBatch clears effective_roles for soft-deleted roles", async () => {
    // Pre-condition: Dave has viewer role from previous tests.
    {
      const cache = await (program.account as any).userPermCache.fetch(daveUpcPda);
      assert.ok(
        hasBit(cache.effectiveRoles as number[], viewerRoleIdx),
        "pre-condition: Dave should have viewer role bit before deletion"
      );
    }

    // Delete viewer role during an update cycle.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await program.methods
      .deleteRole(viewerRoleIdx)
      .accounts({
        roleChunk: roleChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .rpc();

    // Recompute all remaining ACTIVE roles (viewer is now inactive — skipped).
    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Process all users. Bob has editor (chunk 0), Carol and Dave have deleted
    // viewer still in their UA.assigned_roles (chunk 0 provided so entry can be
    // read and checked for active status).
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // After fix: effective_roles must NOT include the deleted viewer role.
    const daveCache = await (program.account as any).userPermCache.fetch(daveUpcPda);
    assert.ok(
      !hasBit(daveCache.effectiveRoles as number[], viewerRoleIdx),
      "deleted role must NOT appear in effective_roles after processRecomputeBatch"
    );

    // has_role must return RoleNotAssigned (not success) for the deleted role.
    try {
      await program.methods
        .hasRole(viewerRoleIdx)
        .accounts({ organization: orgPda, user: dave.publicKey, userPermCache: daveUpcPda })
        .rpc();
      assert.fail("expected RoleNotAssigned for soft-deleted role");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "RoleNotAssigned",
        `Expected RoleNotAssigned for deleted role, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // effective_permissions must also not include viewer role's read permission.
    assert.ok(
      !hasBit(daveCache.effectivePermissions as number[], readPermIdx),
      "deleted role's permissions must be absent from effective_permissions"
    );
  });

  // ---------------------------------------------------------------------------
  // assignUserPermission must reject duplicate direct assignments.
  //
  // set_bit is idempotent so data wouldn't be corrupted, but a spurious
  // UserPermissionGranted event would still be emitted. The handler requires
  // !has_bit(&ua.direct_permissions, permission_index) before setting.
  // ---------------------------------------------------------------------------
  it("assignUserPermission duplicate is rejected with PermissionAlreadyAssigned", async () => {
    // Org is Idle. write permission (1) is active. Bob has no direct perms.
    await program.methods
      .assignUserPermission(writePermIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const ua = await program.account.userAccount.fetch(bobUaPda);
    assert.ok(
      hasBit(ua.directPermissions as number[], writePermIdx),
      "write bit must be set in direct_permissions after first assignment"
    );

    // Second assignment of the same permission must be rejected.
    try {
      await program.methods
        .assignUserPermission(writePermIdx)
        .accounts({
          userAccount: bobUaPda,
          userPermCache: bobUpcPda,
          permChunk: permChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("expected PermissionAlreadyAssigned");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "PermissionAlreadyAssigned",
        `Expected PermissionAlreadyAssigned, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // direct_permissions must still have exactly one grant (bit not duplicated).
    const uaAfter = await program.account.userAccount.fetch(bobUaPda);
    assert.ok(
      hasBit(uaAfter.directPermissions as number[], writePermIdx),
      "write bit must remain set after rejected duplicate"
    );
  });

  // ---------------------------------------------------------------------------
  // removeChildRole must reclaim the 4 bytes freed by swap_remove.
  //
  // add_child_role allocates +4 bytes for the new child_index (u32).
  // Without the resize-down, those 4 bytes (and their rent) would be
  // permanently locked in the RoleChunk.
  // ---------------------------------------------------------------------------
  it("removeChildRole reclaims 4-byte chunk rent on removal", async () => {
    // Need two fresh roles where parent_index > child_index (cycle invariant).
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Fetch roleCount AFTER beginUpdate to get the correct next indices.
    // After step 16, roleCount = 17, so new roles land at indices 17 and 18
    // which are in chunk 1 (17/16 = 1), not chunk 0.
    const orgState = await program.account.organization.fetch(orgPda);
    const childRoleIdx  = orgState.roleCount as number;       // e.g. 17
    const parentRoleIdx = childRoleIdx + 1;                   // e.g. 18
    const newChunkIdx   = Math.floor(parentRoleIdx / ROLES_PER_CHUNK);
    const [newRoleChunkPda] = findRoleChunkPda(program.programId, orgPda, newChunkIdx);

    await program.methods.createRole("child_r", "")
      .accounts({
        roleChunk: newRoleChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods.createRole("parent_r", "")
      .accounts({
        roleChunk: newRoleChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // addChildRole(parent > child) — parent and child are in the same new chunk.
    await program.methods
      .addChildRole(parentRoleIdx, childRoleIdx)
      .accounts({
        roleChunk: newRoleChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([]) // same chunk — no extra account needed
      .rpc();

    const afterAdd = await provider.connection.getAccountInfo(newRoleChunkPda);
    const lenAfterAdd = afterAdd!.data.length;
    const lamAfterAdd = afterAdd!.lamports;

    // removeChildRole — must shrink chunk by 4 bytes and return excess rent.
    await program.methods
      .removeChildRole(parentRoleIdx, childRoleIdx)
      .accounts({
        roleChunk: newRoleChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .rpc();

    const afterRemove = await provider.connection.getAccountInfo(newRoleChunkPda);
    assert.equal(
      afterRemove!.data.length,
      lenAfterAdd - 4,
      "removeChildRole must shrink the RoleChunk by 4 bytes"
    );
    assert.isBelow(
      afterRemove!.lamports,
      lamAfterAdd,
      "removeChildRole must return excess rent lamports to authority"
    );

    // Close the update cycle cleanly.
    await recomputeAllRoles(orgPda);
    await program.methods.commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Process all 3 members. Bob has editor (chunk 0); Carol and Dave still
    // have the deleted viewer (chunk 0) in their assigned_roles.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    await program.methods.finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
  });

  // ---------------------------------------------------------------------------
  // processRecomputeBatch must return excess rent when UA shrinks.
  //
  // When a user's effective_permissions gets shorter (e.g. after a permission
  // is removed from all their roles), the UserAccount is resized down and
  // excess lamports are returned to the authority in the same transaction.
  // ---------------------------------------------------------------------------
  it("processRecomputeBatch returns excess UA rent when effective_permissions shrinks", async () => {
    // Bob currently has: direct write(1) perm (from the duplicate-assignment test) + editor role.
    // Editor role (step 14) has read(0), write(1), admin(2) → effective = [0x07].
    //
    // Step 1 (Idle): revoke Bob's direct write perm.
    // remaining_accounts: [permChunk0 (pcc=1), roleChunk0 (editor role chunk)].
    await program.methods
      .revokeUserPermission(writePermIdx, 1)  // perm_chunk_count=1
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false }, // pcc=1
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false }, // editor role chunk
      ])
      .rpc();

    // Step 2: strip ALL permissions from editor so its effective becomes empty.
    // Editor has read(0), write(1), admin(2) — remove all three.
    const adminPermIdx = 2;
    await program.methods.beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    for (const permIdx of [readPermIdx, writePermIdx, adminPermIdx]) {
      await program.methods
        .removeRolePermission(editorRoleIdx, permIdx)
        .accounts({
          roleChunk: roleChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
        })
        .rpc();
    }

    // Recompute all active roles — editor now has no direct perms → effective = [].
    await recomputeAllRoles(orgPda);

    await program.methods.commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Snapshot Bob's UA before the batch — effective_permissions = [0x07] (1 byte).
    const uaBefore = await provider.connection.getAccountInfo(bobUaPda);
    const lenBefore = uaBefore!.data.length;
    const lamBefore = uaBefore!.lamports;

    // Step 3: processRecomputeBatch with pcc=1.
    // Bob: no direct perms (cleared), editor effective = [] → result = []. UA shrinks.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)  // pcc=1
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false }, // perm chunk (pcc=1)
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    await program.methods.finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Bob's UA must have shrunk (effective_permissions went from [0x07] to []).
    const uaAfter = await provider.connection.getAccountInfo(bobUaPda);
    assert.isBelow(
      uaAfter!.data.length,
      lenBefore,
      "UA data length must decrease when effective_permissions is cleared"
    );
    assert.isBelow(
      uaAfter!.lamports,
      lamBefore,
      "UA lamports must decrease — excess rent returned to authority after shrink"
    );
  });

  // ---------------------------------------------------------------------------
  // processRecomputeBatch must reject a user that was already processed in
  // a prior batch call (AlreadyRecomputed), keeping users_pending_recompute accurate.
  // ---------------------------------------------------------------------------
  it("processRecomputeBatch rejects a user already processed in a prior batch call with AlreadyRecomputed", async () => {
    // Enter Recomputing state.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgAfterCommit = await program.account.organization.fetch(orgPda);
    const pendingBefore = orgAfterCommit.usersPendingRecompute as number;
    assert.equal(pendingBefore, 3, "users_pending_recompute must start at 3 (Bob, Carol, Dave)");

    // Batch 1: process only Bob.  After this his cached_version == target_version.
    await program.methods
      .processRecomputeBatch(Buffer.from([1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    const orgAfterBatch1 = await program.account.organization.fetch(orgPda);
    assert.equal(
      orgAfterBatch1.usersPendingRecompute as number,
      2,
      "counter must be 2 after processing Bob once"
    );

    // Batch 2: submit Bob again — must be rejected with AlreadyRecomputed.
    try {
      await program.methods
        .processRecomputeBatch(Buffer.from([1]), 1)
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts([
          { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
          { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
          { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
          { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        ])
        .rpc();
      assert.fail("expected AlreadyRecomputed");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "AlreadyRecomputed",
        `Expected AlreadyRecomputed, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // The failed transaction was rolled back — counter must still be 2.
    const orgAfterFail = await program.account.organization.fetch(orgPda);
    assert.equal(
      orgAfterFail.usersPendingRecompute as number,
      2,
      "counter must NOT be decremented by the rejected duplicate batch"
    );

    // Process the remaining two users and close the cycle cleanly.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgFinal = await program.account.organization.fetch(orgPda);
    assert.equal(orgFinal.usersPendingRecompute as number, 0, "counter must reach 0 after all users processed");
    assert.deepEqual(orgFinal.state, { idle: {} }, "org must be Idle after finishUpdate");
  });

  // ---------------------------------------------------------------------------
  // processRecomputeBatch requires PermChunks when org has permissions so that
  // soft-deleted permission bits are filtered out.
  // ---------------------------------------------------------------------------
  it("processRecomputeBatch with perm_chunk_count 0 when org has permissions is rejected with PermChunksRequired", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
    await recomputeAllRoles(orgPda);
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    try {
      await program.methods
        .processRecomputeBatch(Buffer.from([0]), 0)
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts([
          { pubkey: bobUaPda, isWritable: true, isSigner: false },
          { pubkey: bobUpcPda, isWritable: true, isSigner: false },
        ])
        .rpc();
      assert.fail("expected PermChunksRequired");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "PermChunksRequired",
        `Expected PermChunksRequired, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    await completeRecomputeCycle(1);
  });

  // ---------------------------------------------------------------------------
  // revoke_role requires PermChunks when org has permissions so that
  // soft-deleted permission bits are filtered out.
  // ---------------------------------------------------------------------------
  it("revokeRole with perm_chunk_count 0 when org has permissions is rejected with PermChunksRequired", async () => {
    try {
      await program.methods
        .revokeRole(editorRoleIdx, 0)
        .accounts({
          userAccount: bobUaPda,
          userPermCache: bobUpcPda,
          roleChunk: roleChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([])
        .rpc();
      assert.fail("expected PermChunksRequired");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "PermChunksRequired",
        `Expected PermChunksRequired, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }
  });

  // ---------------------------------------------------------------------------
  // recompute_role enforces topological order: child roles must be recomputed
  // before their parent (ChildRoleNotRecomputed).
  // ---------------------------------------------------------------------------
  it("recomputeRole rejects parent when child not yet recomputed with ChildRoleNotRecomputed", async () => {
    const org0 = await program.account.organization.fetch(orgPda);
    const roleCountBefore = (org0.roleCount as number);
    const childIdx = roleCountBefore;
    const parentIdx = roleCountBefore + 1;
    const parentChunkIdx = Math.floor(parentIdx / ROLES_PER_CHUNK);
    const [parentChunkPda] = findRoleChunkPda(program.programId, orgPda, parentChunkIdx);

    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Recompute all existing roles FIRST so roles_pending_recompute returns to 0
    // before we create the new child/parent roles.
    await recomputeAllRoles(orgPda);

    const chunkForCreate0 = Math.floor(roleCountBefore / ROLES_PER_CHUNK);
    const [chunkPda0] = findRoleChunkPda(program.programId, orgPda, chunkForCreate0);
    await program.methods
      .createRole("_child", "")
      .accounts({
        roleChunk: chunkPda0,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunkForCreate1 = Math.floor((roleCountBefore + 1) / ROLES_PER_CHUNK);
    const [chunkPda1] = findRoleChunkPda(program.programId, orgPda, chunkForCreate1);
    await program.methods
      .createRole("_parent", "")
      .accounts({
        roleChunk: chunkPda1,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const childChunkIdx = Math.floor(childIdx / ROLES_PER_CHUNK);
    const childChunkPda = childChunkIdx === parentChunkIdx
      ? parentChunkPda
      : findRoleChunkPda(program.programId, orgPda, childChunkIdx)[0];
    const addChildRemaining = childChunkIdx === parentChunkIdx
      ? []
      : [{ pubkey: childChunkPda, isWritable: false, isSigner: false }];

    await program.methods
      .addChildRole(parentIdx, childIdx)
      .accounts({
        roleChunk: parentChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(addChildRemaining)
      .rpc();

    try {
      await program.methods
        .recomputeRole(parentIdx, 1)
        .accounts({
          roleChunk: parentChunkPda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }])
        .rpc();
      assert.fail("expected ChildRoleNotRecomputed");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "ChildRoleNotRecomputed",
        `Expected ChildRoleNotRecomputed, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    const childChunkPdaForRecompute = findRoleChunkPda(program.programId, orgPda, childChunkIdx)[0];
    await program.methods
      .recomputeRole(childIdx, 1)
      .accounts({
        roleChunk: childChunkPdaForRecompute,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }])
      .rpc();

    await program.methods
      .recomputeRole(parentIdx, 1)
      .accounts({
        roleChunk: parentChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts([{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }])
      .rpc();

    await program.methods.commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
    await completeRecomputeCycle(1);
  });

  // ---------------------------------------------------------------------------
  // member_count increments per user; overflow guard uses MemberCountOverflow
  // (same boundary commit_update needs for users_pending_recompute).
  // ---------------------------------------------------------------------------
  it("member_count increments per user and overflow guard uses MemberCountOverflow", async () => {
    // Snapshot member_count before creating a fresh user.
    const orgBefore = await program.account.organization.fetch(orgPda);
    const countBefore = (orgBefore.memberCount as anchor.BN).toNumber();

    // Create a fresh user (Eve) in Idle state.
    const eve = Keypair.generate();
    const eveSig = await provider.connection.requestAirdrop(eve.publicKey, LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(eveSig);

    const [eveUaPda]  = findUserAccountPda(program.programId, orgPda, eve.publicKey);
    const [eveUpcPda] = findUserPermCachePda(program.programId, orgPda, eve.publicKey);

    await program.methods
      .createUserAccount()
      .accounts({
        userAccount:   eveUaPda,
        userPermCache: eveUpcPda,
        organization:  orgPda,
        user:          eve.publicKey,
        authority:     alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const orgAfter = await program.account.organization.fetch(orgPda);
    const countAfter = (orgAfter.memberCount as anchor.BN).toNumber();

    // member_count must have incremented by exactly 1.
    assert.equal(
      countAfter,
      countBefore + 1,
      "member_count must increment by 1 per createUserAccount call"
    );

    // Verify the created account is correct.
    const eveUa = await program.account.userAccount.fetch(eveUaPda);
    assert.ok(eveUa.user.equals(eve.publicKey), "UA.user must match Eve's pubkey");
    assert.ok(eveUa.organization.equals(orgPda),  "UA.organization must match orgPda");

    // Clean up: run a minimal update cycle to bring Eve's cache up to date.
    // (Prevents future tests from seeing a stale Eve cache.)
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Process all 4 members (Bob, Carol, Dave, Eve).
    // Eve has no roles → user_chunk_counts[Eve] = 0.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1, 0]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,   isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,  isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda, isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,  isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda, isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: eveUaPda,   isWritable: true,  isSigner: false },
        { pubkey: eveUpcPda,  isWritable: true,  isSigner: false },
      ])
      .rpc();

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
  });

  // ---------------------------------------------------------------------------
  // commit_update increments permissions_version by exactly 1 each time;
  // VersionOverflow is used when checked_add overflows.
  // ---------------------------------------------------------------------------
  it("permissions_version increments by exactly 1 on each commitUpdate", async () => {
    const orgBefore = await program.account.organization.fetch(orgPda);
    const versionBefore = (orgBefore.permissionsVersion as anchor.BN).toNumber();

    // Run a no-op update cycle.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    await recomputeAllRoles(orgPda);

    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgAfterCommit = await program.account.organization.fetch(orgPda);
    const versionAfterCommit = (orgAfterCommit.permissionsVersion as anchor.BN).toNumber();

    assert.equal(
      versionAfterCommit,
      versionBefore + 1,
      "permissions_version must increment by exactly 1 per commitUpdate"
    );
    assert.deepEqual(orgAfterCommit.state, { recomputing: {} }, "org must be Recomputing after commitUpdate");

    // Complete the cycle: process Bob, Carol, Dave in one call.
    // Eve was created in a prior test; her Keypair is out of scope here,
    // so she is handled by the dynamic stale-UA loop below.
    await program.methods
      .processRecomputeBatch(Buffer.from([1, 1, 1]), 1)
      .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: bobUaPda,      isWritable: true,  isSigner: false },
        { pubkey: bobUpcPda,     isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: carolUaPda,    isWritable: true,  isSigner: false },
        { pubkey: carolUpcPda,   isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: daveUaPda,     isWritable: true,  isSigner: false },
        { pubkey: daveUpcPda,    isWritable: true,  isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();

    // Process any remaining stale users (Eve) via a dynamic lookup.
    const allUAs = await program.account.userAccount.all([
      { memcmp: { offset: 8, bytes: orgPda.toBase58() } },
    ]);
    const targetVersion = (await program.account.organization.fetch(orgPda)).permissionsVersion.toNumber();
    const staleUAs = allUAs.filter(
      (ua: any) => ua.account.cachedVersion.toNumber() < targetVersion
    );

    if (staleUAs.length > 0) {
      const remainingAccts: any[] = [{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }];
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
        .processRecomputeBatch(Buffer.from(counts), 1)
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts(remainingAccts)
        .rpc();
    }

    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgFinal = await program.account.organization.fetch(orgPda);
    assert.deepEqual(orgFinal.state, { idle: {} }, "org must be Idle after finishUpdate");
    assert.equal(
      (orgFinal.permissionsVersion as anchor.BN).toNumber(),
      versionBefore + 1,
      "final permissions_version must equal versionBefore + 1"
    );
  });

  // ---------------------------------------------------------------------------
  // Helper: dynamic full recompute cycle (handles any number of members).
  // ---------------------------------------------------------------------------
  async function fullRecomputeCycle(): Promise<void> {
    await recomputeAllRoles(orgPda);
    await program.methods
      .commitUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const org = await program.account.organization.fetch(orgPda);
    const targetVersion = (org.permissionsVersion as anchor.BN).toNumber();
    const allUAs = await program.account.userAccount.all([
      { memcmp: { offset: 8, bytes: orgPda.toBase58() } },
    ]);
    const staleUAs = allUAs.filter(
      (ua: any) => ua.account.cachedVersion.toNumber() < targetVersion
    );
    if (staleUAs.length > 0) {
      const remainingAccts: any[] = [{ pubkey: permChunk0Pda, isWritable: false, isSigner: false }];
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
        .processRecomputeBatch(Buffer.from(counts), 1)
        .accounts({ organization: orgPda, authority: alice.publicKey, systemProgram: SystemProgram.programId })
        .remainingAccounts(remainingAccts)
        .rpc();
    }
    await program.methods
      .finishUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();
  }

  // ---------------------------------------------------------------------------
  // has_role rejects role_index >= org.role_count with InvalidRoleIndex.
  // (was previously only bounded to 256; now also bounded to role_count)
  // ---------------------------------------------------------------------------
  it("has_role rejects role_index >= org.role_count with InvalidRoleIndex", async () => {
    const org = await program.account.organization.fetch(orgPda);
    const roleCount = org.roleCount as number;

    try {
      await program.methods
        .hasRole(roleCount) // one past the last ever-created role index
        .accounts({
          organization: orgPda,
          user: bob.publicKey,
          userPermCache: bobUpcPda,
        })
        .rpc();
      assert.fail("expected InvalidRoleIndex");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "InvalidRoleIndex",
        `Expected InvalidRoleIndex, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // Large nonsensical index also rejected.
    try {
      await program.methods
        .hasRole(9999)
        .accounts({
          organization: orgPda,
          user: bob.publicKey,
          userPermCache: bobUpcPda,
        })
        .rpc();
      assert.fail("expected InvalidRoleIndex for index 9999");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "InvalidRoleIndex",
        `Expected InvalidRoleIndex for 9999, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }
  });

  // ---------------------------------------------------------------------------
  // remove_child_role rejects a child that is not linked to the parent,
  // returning ChildRoleNotLinked (not the old confusing RoleNotAssigned).
  // ---------------------------------------------------------------------------
  it("remove_child_role rejects non-linked child with ChildRoleNotLinked", async () => {
    // Enter Updating so structural ops are allowed.
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // editor role (index 1) has no children.
    // Trying to remove viewer (index 0) from editor must fail with ChildRoleNotLinked.
    try {
      await program.methods
        .removeChildRole(editorRoleIdx, viewerRoleIdx)
        .accounts({
          roleChunk: roleChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
        })
        .rpc();
      assert.fail("expected ChildRoleNotLinked");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "ChildRoleNotLinked",
        `Expected ChildRoleNotLinked, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // Clean up: exit Updating state with no structural changes.
    await fullRecomputeCycle();
  });

  // ---------------------------------------------------------------------------
  // create_role checked_add: roles_pending_recompute increments correctly
  // (saturating_add replaced with checked_add to detect overflow).
  // ---------------------------------------------------------------------------
  it("create_role increments roles_pending_recompute by 1 for each new role", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const orgBefore = await program.account.organization.fetch(orgPda);
    const pendingBefore = (orgBefore.rolesPendingRecompute as number);
    // All existing roles must already be pending recompute on beginUpdate.
    assert.equal(pendingBefore, orgBefore.activeRoleCount as number,
      "roles_pending_recompute must equal active_role_count after beginUpdate");

    // Recompute existing roles to reset counter before creating a fresh one.
    await recomputeAllRoles(orgPda);

    const orgMid = await program.account.organization.fetch(orgPda);
    assert.equal((orgMid.rolesPendingRecompute as number), 0,
      "roles_pending_recompute must be 0 after recomputing all existing roles");

    // Create one new role — counter must jump from 0 to 1.
    const roleCount = orgMid.roleCount as number;
    const chunkIdx = Math.floor(roleCount / ROLES_PER_CHUNK);
    const [newChunkPda] = findRoleChunkPda(program.programId, orgPda, chunkIdx);
    await program.methods
      .createRole("_pendingTest", "")
      .accounts({
        roleChunk: newChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const orgAfter = await program.account.organization.fetch(orgPda);
    assert.equal((orgAfter.rolesPendingRecompute as number), 1,
      "roles_pending_recompute must be 1 after creating one role");

    // fullRecomputeCycle calls recomputeAllRoles internally; with the idempotent
    // skip guard it will process only the new role (old roles already done above).
    await fullRecomputeCycle();
  });

  // ---------------------------------------------------------------------------
  // add_child_role rejects when children list is at MAX_CHILDREN_PER_ROLE (32).
  // Creates 33 child roles + 1 parent role to exercise the cap.
  // ---------------------------------------------------------------------------
  it("add_child_role rejects with TooManyChildren at cap (32 children)", async () => {
    const MAX_CHILDREN = 32;

    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    // Recompute existing roles first so their pending slots are cleared.
    await recomputeAllRoles(orgPda);

    // Create MAX_CHILDREN + 1 child roles, then 1 parent role (highest index).
    const orgBase = await program.account.organization.fetch(orgPda);
    const baseIdx = orgBase.roleCount as number;

    const createdChunkPdas: PublicKey[] = [];
    for (let i = 0; i <= MAX_CHILDREN; i++) {
      const idx = baseIdx + i;
      const ci = Math.floor(idx / ROLES_PER_CHUNK);
      const [cp] = findRoleChunkPda(program.programId, orgPda, ci);
      createdChunkPdas.push(cp);
      await program.methods
        .createRole(`_cap_child_${i}`, "")
        .accounts({
          roleChunk: cp,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    }

    // Create the parent role (index = baseIdx + MAX_CHILDREN + 1).
    const parentIdx = baseIdx + MAX_CHILDREN + 1;
    const parentChunkIdx = Math.floor(parentIdx / ROLES_PER_CHUNK);
    const [parentChunkPda] = findRoleChunkPda(program.programId, orgPda, parentChunkIdx);
    await program.methods
      .createRole("_cap_parent", "")
      .accounts({
        roleChunk: parentChunkPda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Add MAX_CHILDREN children to the parent — all must succeed.
    for (let i = 0; i < MAX_CHILDREN; i++) {
      const childIdx = baseIdx + i;
      const childChunkIdx = Math.floor(childIdx / ROLES_PER_CHUNK);
      const crossChunk = childChunkIdx !== parentChunkIdx;
      const [childChunkPda] = findRoleChunkPda(program.programId, orgPda, childChunkIdx);
      const remaining = crossChunk
        ? [{ pubkey: childChunkPda, isWritable: false, isSigner: false }]
        : [];
      await program.methods
        .addChildRole(parentIdx, childIdx)
        .accounts({
          roleChunk: parentChunkPda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(remaining)
        .rpc();
    }

    // The (MAX_CHILDREN + 1)th add must fail with TooManyChildren.
    const extraChildIdx = baseIdx + MAX_CHILDREN; // the unused 33rd child
    const extraChildChunkIdx = Math.floor(extraChildIdx / ROLES_PER_CHUNK);
    const crossChunk = extraChildChunkIdx !== parentChunkIdx;
    const [extraChildChunkPda] = findRoleChunkPda(program.programId, orgPda, extraChildChunkIdx);
    const extraRemaining = crossChunk
      ? [{ pubkey: extraChildChunkPda, isWritable: false, isSigner: false }]
      : [];
    try {
      await program.methods
        .addChildRole(parentIdx, extraChildIdx)
        .accounts({
          roleChunk: parentChunkPda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(extraRemaining)
        .rpc();
      assert.fail("expected TooManyChildren");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "TooManyChildren",
        `Expected TooManyChildren, got: ${(err as AnchorError).error.errorCode.code}`
      );
    }

    // Clean up: recompute all roles and complete the cycle.
    await fullRecomputeCycle();
  });

  // ---------------------------------------------------------------------------
  // Fix H-1: revokeUserPermission requires PermChunks when org has permissions.
  // Calling with pcc=0 when next_permission_index > 0 must fail PermChunksRequired.
  // ---------------------------------------------------------------------------
  it("revokeUserPermission with pcc=0 when org has permissions is rejected with PermChunksRequired", async () => {
    // Give Bob a direct write permission so there is something to revoke.
    await program.methods
      .assignUserPermission(writePermIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Calling with pcc=0 must be rejected because org has permissions (next_permission_index > 0).
    try {
      await program.methods
        .revokeUserPermission(writePermIdx, 0)
        .accounts({
          userAccount: bobUaPda,
          userPermCache: bobUpcPda,
          organization: orgPda,
          authority: alice.publicKey,
        })
        .remainingAccounts([])
        .rpc();
      assert.fail("expected PermChunksRequired");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "PermChunksRequired"
      );
    }

    // Clean up: revoke correctly with pcc=1.
    await program.methods
      .revokeUserPermission(writePermIdx, 1)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();
  });

  // ---------------------------------------------------------------------------
  // Fix H-2: remaining_accounts slice bounds validated before indexing.
  // Passing pcc > remaining_accounts.len() must fail with AccountCountMismatch.
  // ---------------------------------------------------------------------------
  it("assignRole with pcc exceeding remaining_accounts length is rejected with AccountCountMismatch", async () => {
    try {
      // perm_chunk_count=5 but zero remaining_accounts provided — triggers bounds check.
      await program.methods
        .assignRole(editorRoleIdx, 5)
        .accounts({
          userAccount: carolUaPda,
          userPermCache: carolUpcPda,
          roleChunk: roleChunk0Pda,
          organization: orgPda,
          authority: alice.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts([])
        .rpc();
      assert.fail("expected AccountCountMismatch");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "AccountCountMismatch"
      );
    }
  });

  // ---------------------------------------------------------------------------
  // Fix M-1: org PDA seeds include the creator pubkey so different admins can
  // create orgs with the same name without collision.
  // ---------------------------------------------------------------------------
  it("two admins can create orgs with the same name without PDA collision", async () => {
    const otherAdmin = Keypair.generate();
    const fundSig = await provider.connection.requestAirdrop(otherAdmin.publicKey, LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(fundSig);

    const sharedName = "shared_org_test";
    const [aliceSharedOrgPda] = findOrgPda(program.programId, alice.publicKey, sharedName);
    const [otherSharedOrgPda] = findOrgPda(program.programId, otherAdmin.publicKey, sharedName);

    assert.notEqual(
      aliceSharedOrgPda.toBase58(),
      otherSharedOrgPda.toBase58(),
      "same org name with different admins must produce distinct PDAs"
    );

    await program.methods
      .initializeOrganization(sharedName, 0)
      .accounts({
        organization: aliceSharedOrgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    await program.methods
      .initializeOrganization(sharedName, 0)
      .accounts({
        organization: otherSharedOrgPda,
        authority: otherAdmin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([otherAdmin])
      .rpc();

    const aliceOrg = await program.account.organization.fetch(aliceSharedOrgPda);
    const otherOrg = await program.account.organization.fetch(otherSharedOrgPda);
    assert.ok(aliceOrg.superAdmin.equals(alice.publicKey));
    assert.ok(otherOrg.superAdmin.equals(otherAdmin.publicKey));
    assert.ok((aliceOrg as any).originalAdmin.equals(alice.publicKey));
    assert.ok((otherOrg as any).originalAdmin.equals(otherAdmin.publicKey));
  });

  // ---------------------------------------------------------------------------
  // Fix M-2: deleteResource closes the account to resource.creator, not authority.
  // Passing a wrong resource_creator account must fail with NotResourceCreator.
  // ---------------------------------------------------------------------------
  it("deleteResource rejects wrong resource_creator and closes to the correct creator", async () => {
    // Grant Bob write permission so he can create/delete resources.
    await program.methods
      .assignUserPermission(writePermIdx)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        permChunk: permChunk0Pda,
        organization: orgPda,
        authority: alice.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const resourceId = new anchor.BN(80001);
    const [resourcePda] = findResourcePda(program.programId, orgPda, resourceId);

    await program.methods
      .createResource("creator_test", resourceId, writePermIdx)
      .accounts({
        resource: resourcePda,
        organization: orgPda,
        userPermCache: bobUpcPda,
        authority: bob.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([bob])
      .rpc();

    const res = await program.account.resource.fetch(resourcePda);
    assert.ok(res.creator.equals(bob.publicKey), "resource.creator must be Bob");

    // Attempt to delete while passing Carol (not the creator) as resource_creator.
    try {
      await program.methods
        .deleteResource()
        .accounts({
          resource: resourcePda,
          organization: orgPda,
          userPermCache: bobUpcPda,
          authority: bob.publicKey,
          resourceCreator: carol.publicKey,
        })
        .signers([bob])
        .rpc();
      assert.fail("expected NotResourceCreator");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal(
        (err as AnchorError).error.errorCode.code,
        "NotResourceCreator"
      );
    }

    // Correct deletion: resource_creator == resource.creator (Bob).
    await program.methods
      .deleteResource()
      .accounts({
        resource: resourcePda,
        organization: orgPda,
        userPermCache: bobUpcPda,
        authority: bob.publicKey,
        resourceCreator: bob.publicKey,
      })
      .signers([bob])
      .rpc();

    // Resource account must be closed.
    const closed = await provider.connection.getAccountInfo(resourcePda);
    assert.isNull(closed, "resource account must be closed after deleteResource");

    // Clean up: revoke write perm from Bob.
    await program.methods
      .revokeUserPermission(writePermIdx, 1)
      .accounts({
        userAccount: bobUaPda,
        userPermCache: bobUpcPda,
        organization: orgPda,
        authority: alice.publicKey,
      })
      .remainingAccounts([
        { pubkey: permChunk0Pda, isWritable: false, isSigner: false },
        { pubkey: roleChunk0Pda, isWritable: false, isSigner: false },
      ])
      .rpc();
  });

  // ---------------------------------------------------------------------------
  // Fix L-1: transferSuperAdmin changes authority while keeping org PDA stable.
  // The originalAdmin field is set at init and never changes.
  // ---------------------------------------------------------------------------
  it("transferSuperAdmin changes authority, old admin is rejected, and transfer back restores access", async () => {
    const orgBefore = await program.account.organization.fetch(orgPda);
    assert.ok(orgBefore.superAdmin.equals(alice.publicKey));
    assert.ok((orgBefore as any).originalAdmin.equals(alice.publicKey));

    // Transfer to Bob.
    await program.methods
      .transferSuperAdmin()
      .accounts({
        organization: orgPda,
        newSuperAdmin: bob.publicKey,
        authority: alice.publicKey,
      })
      .rpc();

    const orgAfter = await program.account.organization.fetch(orgPda);
    assert.ok(orgAfter.superAdmin.equals(bob.publicKey), "superAdmin must be Bob after transfer");
    assert.ok((orgAfter as any).originalAdmin.equals(alice.publicKey), "originalAdmin must remain Alice");

    // Alice (old admin) must be rejected for super_admin-gated ops.
    try {
      await program.methods
        .beginUpdate()
        .accounts({ organization: orgPda, authority: alice.publicKey })
        .rpc();
      assert.fail("expected NotSuperAdmin for Alice");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "NotSuperAdmin");
    }

    // Passing the same pubkey as new_super_admin must fail with AlreadySuperAdmin.
    try {
      await program.methods
        .transferSuperAdmin()
        .accounts({
          organization: orgPda,
          newSuperAdmin: bob.publicKey,
          authority: bob.publicKey,
        })
        .signers([bob])
        .rpc();
      assert.fail("expected AlreadySuperAdmin");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "AlreadySuperAdmin");
    }

    // Transfer back to Alice (org is still Idle — no update cycle started).
    await program.methods
      .transferSuperAdmin()
      .accounts({
        organization: orgPda,
        newSuperAdmin: alice.publicKey,
        authority: bob.publicKey,
      })
      .signers([bob])
      .rpc();

    const orgRestored = await program.account.organization.fetch(orgPda);
    assert.ok(orgRestored.superAdmin.equals(alice.publicKey), "superAdmin must be Alice again");
    assert.ok((orgRestored as any).originalAdmin.equals(alice.publicKey));
  });

  // ---------------------------------------------------------------------------
  // Fix L-2: manage_roles_permission is stored per-org and read at delegation time
  // instead of using a hardcoded constant.
  // ---------------------------------------------------------------------------
  it("organization.manageRolesPermission reflects the value set at initialization", async () => {
    const org = await program.account.organization.fetch(orgPda);
    // acme_corp was initialized with manage_roles_permission = 3
    assert.equal(
      (org as any).manageRolesPermission as number,
      3,
      "manageRolesPermission must equal the value passed to initializeOrganization"
    );

    // originalAdmin was also set at init and must equal the creator.
    assert.ok(
      (org as any).originalAdmin.equals(alice.publicKey),
      "originalAdmin must be Alice (org creator)"
    );

    // Create a fresh org with a different manage_roles_permission to confirm
    // the field is truly per-org and not a shared constant.
    const freshAdmin = Keypair.generate();
    const freshSig = await provider.connection.requestAirdrop(freshAdmin.publicKey, LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(freshSig);

    const freshOrgName = "fresh_mrp_org";
    const [freshOrgPda] = findOrgPda(program.programId, freshAdmin.publicKey, freshOrgName);

    await program.methods
      .initializeOrganization(freshOrgName, 7)
      .accounts({
        organization: freshOrgPda,
        authority: freshAdmin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([freshAdmin])
      .rpc();

    const freshOrg = await program.account.organization.fetch(freshOrgPda);
    assert.equal(
      (freshOrg as any).manageRolesPermission as number,
      7,
      "fresh org must store manage_roles_permission = 7"
    );
  });

  // ---------------------------------------------------------------------------
  // Fix L-3: createResource and deleteResource require OrgState::Idle.
  // Calling either during an active update cycle must fail with OrgNotIdle.
  // ---------------------------------------------------------------------------
  it("createResource is rejected during Updating state with OrgNotIdle", async () => {
    await program.methods
      .beginUpdate()
      .accounts({ organization: orgPda, authority: alice.publicKey })
      .rpc();

    const resourceId = new anchor.BN(77001);
    const [resourcePda] = findResourcePda(program.programId, orgPda, resourceId);

    try {
      await program.methods
        .createResource("should_fail", resourceId, writePermIdx)
        .accounts({
          resource: resourcePda,
          organization: orgPda,
          userPermCache: bobUpcPda,
          authority: bob.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([bob])
        .rpc();
      assert.fail("expected OrgNotIdle");
    } catch (err) {
      assert.instanceOf(err, AnchorError);
      assert.equal((err as AnchorError).error.errorCode.code, "OrgNotIdle");
    }

    // Exit Updating state cleanly.
    await fullRecomputeCycle();
  });
});
