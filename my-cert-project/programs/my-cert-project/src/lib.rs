use anchor_lang::prelude::*;
use anchor_lang::solana_program::clock::Clock;

declare_id!("Fg61jXm97N325G3z8r3K8v9bL65j4P5v8T32w4V7k9m2");

#[program]
pub mod cert_program {
    use super::*;

    pub fn issue_certificate(
        ctx: Context<IssueCertificate>,
        cert_id: String,
        data_hash: String,
        encrypted_cid: String,
        metadata_ipfs_cid: String,
        serial_number: u64,
    ) -> Result<()> {
        let certificate_account = &mut ctx.accounts.certificate_account;

        certificate_account.cert_id = cert_id;
        certificate_account.issuer = *ctx.accounts.issuer.key;
        certificate_account.data_hash = data_hash;
        certificate_account.encrypted_cid = encrypted_cid;
        certificate_account.metadata_ipfs_cid = metadata_ipfs_cid;
        certificate_account.status = CertificateStatus::Issued;
        certificate_account.issued_at = Clock::get()?.unix_timestamp;
        certificate_account.serial_number = serial_number;

        emit!(CertificateIssued {
            cert_id: certificate_account.cert_id.clone(),
            issuer: certificate_account.issuer,
            serial_number: certificate_account.serial_number,
        });

        msg!("Certificate issued for ID: {}", certificate_account.cert_id);
        Ok(())
    }

    pub fn revoke_certificate(
        ctx: Context<RevokeCertificate>,
        _cert_id: String,
    ) -> Result<()> {
        let certificate_account = &mut ctx.accounts.certificate_account;
        require_keys_eq!(certificate_account.issuer, *ctx.accounts.issuer.key, CertError::UnauthorizedIssuer);

        certificate_account.status = CertificateStatus::Revoked;

        emit!(CertificateRevoked {
            cert_id: certificate_account.cert_id.clone(),
            issuer: certificate_account.issuer,
        });

        msg!("Certificate with ID {} has been revoked.", certificate_account.cert_id);
        Ok(())
    }

    pub fn verify_certificate(
        ctx: Context<VerifyCertificate>,
        _cert_id: String,
        data_hash: String,
    ) -> Result<()> {
        let certificate_account = &ctx.accounts.certificate_account;

        require_eq!(certificate_account.status, CertificateStatus::Issued, CertError::CertificateRevoked);
        require_eq!(certificate_account.data_hash, data_hash, CertError::HashMismatch);

        msg!("Certificate is valid.");
        Ok(())
    }
}

// Accounts
#[derive(Accounts)]
#[instruction(cert_id: String)]
pub struct IssueCertificate<'info> {
    #[account(
        init,
        payer = issuer,
        space = 8 + 32 + 4 + cert_id.len() + 4 + 64 + 4 + 64 + 4 + 64 + 1 + 8 + 8,
        seeds = [b"certificate", cert_id.as_bytes()],
        bump
    )]
    pub certificate_account: Account<'info, Certificate>,
    #[account(mut)]
    pub issuer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_cert_id: String)]
pub struct RevokeCertificate<'info> {
    #[account(
        mut,
        seeds = [b"certificate", _cert_id.as_bytes()],
        bump
    )]
    pub certificate_account: Account<'info, Certificate>,
    pub issuer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(_cert_id: String)]
pub struct VerifyCertificate<'info> {
    #[account(
        seeds = [b"certificate", _cert_id.as_bytes()],
        bump
    )]
    pub certificate_account: Account<'info, Certificate>,
}

// Data Structures
#[account]
pub struct Certificate {
    pub cert_id: String,
    pub issuer: Pubkey,
    pub data_hash: String,
    pub encrypted_cid: String,
    pub metadata_ipfs_cid: String,
    pub status: CertificateStatus,
    pub issued_at: i64,
    pub serial_number: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    Issued,
    Revoked,
}

// Events
#[event]
pub struct CertificateIssued {
    pub cert_id: String,
    pub issuer: Pubkey,
    pub serial_number: u64,
}

#[event]
pub struct CertificateRevoked {
    pub cert_id: String,
    pub issuer: Pubkey,
}

// Errors
#[error_code]
pub enum CertError {
    #[msg("You are not authorized to perform this action.")]
    UnauthorizedIssuer,
    #[msg("The provided hash does not match the stored hash.")]
    HashMismatch,
    #[msg("This certificate has been revoked.")]
    CertificateRevoked,
}