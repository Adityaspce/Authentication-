import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CertProgram } from "../target/types/cert_program";
import { SystemProgram, PublicKey } from "@solana/web3.js";
import { assert } from "chai";

describe("cert_program", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.CertProgram as Program<CertProgram>;
    const admin = provider.wallet;

    let issuerRegistryPda: PublicKey;
    let certificatePda: PublicKey;

    const issuerName = "ACME University";
    const serialNumber = "SN12345";
    const studentName = "John Doe";
    const courseName = "Blockchain Development";

    it("1. Initializes and registers a new issuer", async () => {
        [issuerRegistryPda] = PublicKey.findProgramAddressSync([Buffer.from("issuer_registry"), admin.publicKey.toBuffer()], program.programId);

        await program.methods
            .initializeIssuer(issuerName)
            .accounts({
                issuerRegistry: issuerRegistryPda,
                signer: admin.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .rpc();

        const issuerRegistryData = await program.account.issuerRegistry.fetch(issuerRegistryPda);
        assert.equal(issuerRegistryData.issuerKey.toString(), admin.publicKey.toString());
        assert.equal(issuerRegistryData.name, issuerName);

        console.log("Issuer registered successfully!");
    });

    it("2. Issues a new certificate", async () => {
        [certificatePda] = PublicKey.findProgramAddressSync([Buffer.from("certificate"), admin.publicKey.toBuffer(), Buffer.from(serialNumber)], program.programId);

        await program.methods
            .issueCertificate(serialNumber, studentName, courseName)
            .accounts({
                certificateAccount: certificatePda,
                issuerRegistry: issuerRegistryPda,
                signer: admin.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .rpc();

        const certificateData = await program.account.certificateAccount.fetch(certificatePda);
        assert.equal(certificateData.serialNumber, serialNumber);
        assert.equal(certificateData.issuerKey.toString(), admin.publicKey.toString());
        assert.isFalse(certificateData.isRevoked);

        console.log("Certificate issued successfully!");
    });

    it("3. Revokes a certificate", async () => {
        // Revoke the certificate
        await program.methods
            .revokeCertificate(serialNumber)
            .accounts({
                certificateAccount: certificatePda,
                issuerRegistry: issuerRegistryPda,
                signer: admin.publicKey,
            })
            .rpc();

        const revokedCertificateData = await program.account.certificateAccount.fetch(certificatePda);
        assert.isTrue(revokedCertificateData.isRevoked);
        console.log("Certificate revoked successfully!");
    });
});