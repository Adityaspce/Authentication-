import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CertProgram } from "../target/types/cert_program";
import { assert } from "chai";

describe("cert_program", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.CertProgram as Program<CertProgram>;

  // Generate keypairs for the issuer and another random user
  const issuer = anchor.web3.Keypair.generate();
  const unauthorizedUser = anchor.web3.Keypair.generate();

  // Test data for the certificate
  const certId = "TEST-CERT-001";
  const dataHash = "579b189a071192e44d31ae3f3a8b4a2e54e4b52b314945d81b95f2d7a22964a7";
  const encryptedCid = "QmZk2F5nQ7T3w9B8H4k5e9p6r7s8t9u0v1w2x3y4z5a6b7c8d";
  const metadataIpfsCid = "QmbP3mQ5h7j8k9L0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b";
  const serialNumber = new anchor.BN(123456789);

  // Helper function to create the certificate PDA
  const getCertificatePda = async (certId: string) => {
    return (
      await anchor.web3.PublicKey.findProgramAddress(
        [anchor.utils.bytes.utf8.encode("certificate"), anchor.utils.bytes.utf8.encode(certId)],
        program.programId
      )
    )[0];
  };

  before(async () => {
    // Airdrop SOL to both the issuer and the unauthorized user for rent payments
    await provider.connection.requestAirdrop(
      issuer.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.requestAirdrop(
      unauthorizedUser.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
  });

  // Test Case 1: Issue a new certificate
  it("Is able to issue a new certificate!", async () => {
    const certificatePda = await getCertificatePda(certId);

    await program.methods
      .issueCertificate(certId, dataHash, encryptedCid, metadataIpfsCid, serialNumber)
      .accounts({
        certificateAccount: certificatePda,
        issuer: issuer.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([issuer])
      .rpc();

    // Fetch the newly created account and check its data
    const certificateAccount = await program.account.certificate.fetch(certificatePda);

    assert.equal(certificateAccount.certId, certId);
    assert.equal(certificateAccount.issuer.toBase58(), issuer.publicKey.toBase58());
    assert.equal(certificateAccount.dataHash, dataHash);
    assert.equal(certificateAccount.encryptedCid, encryptedCid);
    assert.equal(certificateAccount.metadataIpfsCid, metadataIpfsCid);
    assert.equal(certificateAccount.serialNumber.toNumber(), serialNumber.toNumber());
    assert.deepEqual(certificateAccount.status, { issued: {} });
  });

  // Test Case 2: Verify a certificate with the correct hash
  it("A certificate can be verified successfully", async () => {
    const certificatePda = await getCertificatePda(certId);

    // This call should succeed without throwing an error
    await program.methods
      .verifyCertificate(certId, dataHash)
      .accounts({
        certificateAccount: certificatePda,
      })
      .rpc();

    // If the RPC call doesn't throw, the test passes
    assert.isTrue(true);
  });

  // Test Case 3: Fail to verify with an invalid hash
  it("A certificate cannot be verified with an invalid hash", async () => {
    const certificatePda = await getCertificatePda(certId);
    const invalidHash = "invalid-hash";

    try {
      await program.methods
        .verifyCertificate(certId, invalidHash)
        .accounts({
          certificateAccount: certificatePda,
        })
        .rpc();
      // If the RPC call succeeds, the test should fail
      assert.fail("Verification should have failed with an invalid hash.");
    } catch (err) {
      assert.include(err.message, "The provided hash does not match the stored hash.", "Error message should indicate invalid hash.");
    }
  });

  // Test Case 4: Revoke a certificate by the original issuer
  it("A certificate can be revoked by the issuer", async () => {
    const certificatePda = await getCertificatePda(certId);

    await program.methods
      .revokeCertificate(certId)
      .accounts({
        certificateAccount: certificatePda,
        issuer: issuer.publicKey,
      })
      .signers([issuer])
      .rpc();

    const certificateAccount = await program.account.certificate.fetch(certificatePda);
    assert.deepEqual(certificateAccount.status, { revoked: {} });
  });

  // Test Case 5: Fail to verify a revoked certificate
  it("A revoked certificate cannot be verified", async () => {
    const certificatePda = await getCertificatePda(certId);

    try {
      await program.methods
        .verifyCertificate(certId, dataHash)
        .accounts({
          certificateAccount: certificatePda,
        })
        .rpc();
      assert.fail("Verification should have failed for a revoked certificate.");
    } catch (err) {
      assert.include(err.message, "This certificate has been revoked.", "Error message should indicate revoked status.");
    }
  });

  // Test Case 6: Fail to revoke a certificate by an unauthorized user
  it("A certificate cannot be revoked by an unauthorized user", async () => {
    const certIdUnauthorized = "TEST-CERT-UNAUTH";
    // First, issue a new certificate for this test
    const certificatePda = await getCertificatePda(certIdUnauthorized);
    await program.methods
      .issueCertificate(certIdUnauthorized, dataHash, encryptedCid, metadataIpfsCid, new anchor.BN(9876))
      .accounts({
        certificateAccount: certificatePda,
        issuer: issuer.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([issuer])
      .rpc();

    try {
      // Try to revoke the certificate using the unauthorizedUser's keypair
      await program.methods
        .revokeCertificate(certIdUnauthorized)
        .accounts({
          certificateAccount: certificatePda,
          issuer: unauthorizedUser.publicKey,
        })
        .signers([unauthorizedUser])
        .rpc();
      assert.fail("Revocation should have failed for an unauthorized user.");
    } catch (err) {
      assert.include(err.message, "You are not authorized to perform this action.", "Error message should indicate unauthorized issuer.");
    }
  });
});