use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod cert_program {
    use super::*;

    pub fn initialize_issuer(ctx: Context<InitializeIssuer>, name: String) -> Result<()> {
        let issuer_registry = &mut ctx.accounts.issuer_registry;
        issuer_registry.issuer_key = ctx.accounts.signer.key();
        issuer_registry.name = name;
        Ok(())
    }

    pub fn issue_certificate(
        ctx: Context<IssueCertificate>,
        serial_number: String,
        student_name: String,
        course_name: String,
    ) -> Result<()> {
        let certificate = &mut ctx.accounts.certificate_account;
        certificate.serial_number = serial_number;
        certificate.student_name = student_name;
        certificate.course_name = course_name;
        certificate.issuer_key = ctx.accounts.signer.key();
        certificate.is_revoked = false;
        Ok(())
    }

    pub fn revoke_certificate(
        ctx: Context<RevokeCertificate>,
        _serial_number: String,
    ) -> Result<()> {
        let certificate = &mut ctx.accounts.certificate_account;
        certificate.is_revoked = true;
        Ok(())
    }

    pub fn verify_certificate(
        ctx: Context<VerifyCertificate>,
        _serial_number: String,
    ) -> Result<bool> {
        let certificate = &ctx.accounts.certificate_account;
        Ok(!certificate.is_revoked)
    }
}

#[derive(Accounts)]
#[instruction(name: String)]
pub struct InitializeIssuer<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 32 + 4 + name.len(),
        seeds = [b"issuer_registry", signer.key().as_ref()],
        bump
    )]
    pub issuer_registry: Account<'info, IssuerRegistry>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(serial_number: String)]
pub struct IssueCertificate<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 4 + serial_number.len() + 4 + 64 + 4 + 64 + 32 + 1,
        seeds = [b"certificate", signer.key().as_ref(), serial_number.as_bytes()],
        bump
    )]
    pub certificate_account: Account<'info, CertificateAccount>,
    #[account(
        seeds = [b"issuer_registry", signer.key().as_ref()],
        bump,
        constraint = issuer_registry.issuer_key == signer.key() @ ErrorCode::UnauthorizedIssuer,
    )]
    pub issuer_registry: Account<'info, IssuerRegistry>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(serial_number: String)]
pub struct RevokeCertificate<'info> {
    #[account(
        mut,
        seeds = [b"certificate", certificate_account.issuer_key.as_ref(), serial_number.as_bytes()],
        bump,
        constraint = certificate_account.issuer_key == signer.key() @ ErrorCode::UnauthorizedIssuer,
    )]
    pub certificate_account: Account<'info, CertificateAccount>,
    #[account(
        seeds = [b"issuer_registry", signer.key().as_ref()],
        bump,
        constraint = issuer_registry.issuer_key == signer.key() @ ErrorCode::UnauthorizedIssuer,
    )]
    pub issuer_registry: Account<'info, IssuerRegistry>,
    #[account(mut)]
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(serial_number: String)]
pub struct VerifyCertificate<'info> {
    #[account(
        seeds = [b"certificate", issuer_registry.key().as_ref(), serial_number.as_bytes()],
        bump
    )]
    pub certificate_account: Account<'info, CertificateAccount>,
    #[account(
        seeds = [b"issuer_registry", issuer_registry.key().as_ref()],
        bump
    )]
    pub issuer_registry: Account<'info, IssuerRegistry>,
}

#[account]
pub struct IssuerRegistry {
    pub issuer_key: Pubkey,
    pub name: String,
}

#[account]
pub struct CertificateAccount {
    pub serial_number: String,
    pub student_name: String,
    pub course_name: String,
    pub issuer_key: Pubkey,
    pub is_revoked: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized issuer trying to perform this action")]
    UnauthorizedIssuer,
}