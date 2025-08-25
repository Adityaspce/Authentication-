import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CertProgram } from "../target/types/cert_program";
import { assert } from "chai"; // Assuming you are using chai for assertions

describe("cert_program", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.CertProgram as Program<CertProgram>;
  
  // Create a new keypair for the issuer for each test run
  // This ensures a clean state and avoids relying on a pre-funded wallet
  const issuer = anchor.web3.Keypair.generate(); 
  let certificateAccountPDA: anchor.web3.PublicKey; // To store the PDA for the certificate
  let certificateId = "testcert123";
  let dataHash = "some_data_hash_123";
  let encryptedCid = "QmEncryptedCID";
  let metadataIpfsCid = "QmMetadataIPFSCID";
  let serialNumber = new anchor.BN(1); // Use BN for u64


  // --- FUND THE ISSUER BEFORE ALL TESTS ---
  before(async () => {
    // Airdrop SOL to the issuer to cover rent exemption for the certificate account
    const airdropSignature = await program.provider.connection.requestAirdrop(
      issuer.publicKey,
      anchor.web3.LAMPORTS_PER_SOL * 2 // Airdrop 2 SOL (adjust if needed, 0.003 SOL is roughly 3M lamports)
    );
    await program.provider.connection.confirmTransaction(airdropSignature, "confirmed");
    console.log(`Airdropped SOL to issuer: ${issuer.publicKey.toBase58()}`);

    // Derive the PDA for the certificate account
    const [pda, _] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("certificate"), Buffer.from(certificateId)],
      program.programId
    );
    certificateAccountPDA = pda;
  });
  // ----------------------------------------


  it("Is able to issue a new certificate!", async () => {
    // Add your test logic here.
    // Ensure `issue_certificate` is called with the `issuer` as signer and payer.
    await program.methods
      .issueCertificate(
        certificateId,
        dataHash,
        encryptedCid,
        metadataIpfsCid,
        serialNumber
      )
      .accounts({
        certificateAccount: certificateAccountPDA,
        issuer: issuer.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([issuer])
      .rpc();

    // Fetch the account to verify
    const certificate = await program.account.certificate.fetch(
      certificateAccountPDA
    );

    assert.equal(certificate.certId, certificateId);
    assert.equal(certificate.issuer.toBase58(), issuer.publicKey.toBase58());
    assert.equal(certificate.dataHash, dataHash);
    assert.equal(certificate.encryptedCid, encryptedCid);
    assert.equal(certificate.metadataIpfsCid, metadataIpfsCid);
    assert.deepEqual(certificate.status, { issued: {} }); // For enum comparison
    assert.equal(certificate.serialNumber.toNumber(), serialNumber.toNumber());
  });

  it("A certificate can be verified successfully", async () => {
    await program.methods
      .verifyCertificate(certificateId, dataHash)
      .accounts({
        certificateAccount: certificateAccountPDA,
      })
      .rpc();
    // If no error is thrown, the verification is successful
  });

  it("A certificate cannot be verified with an invalid hash", async () => {
    const invalidDataHash = "invalid_data_hash";
    try {
      await program.methods
        .verifyCertificate(certificateId, invalidDataHash)
        .accounts({
          certificateAccount: certificateAccountPDA,
        })
        .rpc();
      assert.fail("Verification should have failed with invalid hash");
    } catch (error) {
      assert.include(error.logs.toString(), "The provided hash does not match the stored hash.", "Error message should indicate invalid hash.");
    }
  });

  it("A certificate can be revoked by the issuer", async () => {
    await program.methods
      .revokeCertificate(certificateId)
      .accounts({
        certificateAccount: certificateAccountPDA,
        issuer: issuer.publicKey,
      })
      .signers([issuer])
      .rpc();

    const certificate = await program.account.certificate.fetch(
      certificateAccountPDA
    );
    assert.deepEqual(certificate.status, { revoked: {} }); // For enum comparison
  });

  it("A revoked certificate cannot be verified", async () => {
    try {
      await program.methods
        .verifyCertificate(certificateId, dataHash)
        .accounts({
          certificateAccount: certificateAccountPDA,
        })
        .rpc();
      assert.fail("Verification should have failed for a revoked certificate");
    } catch (error) {
        assert.include(error.logs.toString(), "This certificate has been revoked.", "Error message should indicate revoked status.");
    }
  });

  it("A certificate cannot be revoked by an unauthorized user", async () => {
    const unauthorizedUser = anchor.web3.Keypair.generate();

    // Airdrop SOL to the unauthorized user to pay for transaction fees
    const airdropSignature = await program.provider.connection.requestAirdrop(
      unauthorizedUser.publicKey,
      anchor.web3.LAMPORTS_PER_SOL // Airdrop 1 SOL
    );
    await program.provider.connection.confirmTransaction(airdropSignature, "confirmed");


    try {
      await program.methods
        .revokeCertificate(certificateId)
        .accounts({
          certificateAccount: certificateAccountPDA,
          issuer: unauthorizedUser.publicKey, // Unauthorized user attempts to revoke
        })
        .signers([unauthorizedUser])
        .rpc();
      assert.fail("Revocation by unauthorized user should have failed");
    } catch (error) {
      assert.include(error.logs.toString(), "You are not authorized to perform this action.", "Error message should indicate unauthorized issuer.");
    }
  });
});
