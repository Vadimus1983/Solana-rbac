use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct CreatePermission<'info> {
    /// CHECK: PDA seeds verified. Initialized on first use and grown on each call in the handler.
    #[account(
        mut,
        seeds = [
            b"perm_chunk",
            organization.key().as_ref(),
            &(organization.next_permission_index / PERMS_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump,
    )]
    pub perm_chunk: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"organization", organization.name.as_bytes()],
        bump = organization.bump,
        constraint = authority.key() == organization.super_admin @ RbacError::NotSuperAdmin,
    )]
    pub organization: Account<'info, Organization>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<CreatePermission>, name: String, description: String) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Updating, RbacError::OrgNotInUpdateMode);
    require!(name.len() <= MAX_PERMISSION_NAME_LEN, RbacError::PermissionNameTooLong);
    require!(description.len() <= MAX_PERMISSION_DESC_LEN, RbacError::PermissionDescTooLong);

    require!(org.next_permission_index < 256, RbacError::InvalidPermissionIndex);

    let perm_index = org.next_permission_index;
    let chunk_idx = perm_index / PERMS_PER_CHUNK as u32;

    org.next_permission_index = perm_index
        .checked_add(1)
        .ok_or(error!(RbacError::InvalidPermissionIndex))?;

    let new_entry = PermEntry {
        index: perm_index,
        name: name.clone(),
        description: description.clone(),
        created_by: ctx.accounts.authority.key(),
        active: true,
    };
    let entry_size = new_entry.serialized_size();

    let chunk_info = ctx.accounts.perm_chunk.to_account_info();

    // Create the account the first time this chunk index is used.
    if chunk_info.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(PermChunk::BASE_SIZE);
        let chunk_idx_bytes = chunk_idx.to_le_bytes();
        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.authority.to_account_info(),
                    to: chunk_info.clone(),
                },
                &[&[
                    b"perm_chunk",
                    ctx.accounts.organization.key().as_ref(),
                    &chunk_idx_bytes,
                    &[ctx.bumps.perm_chunk],
                ]],
            ),
            lamports,
            PermChunk::BASE_SIZE as u64,
            ctx.program_id,
        )?;
        let init_chunk = PermChunk {
            organization: ctx.accounts.organization.key(),
            chunk_index: chunk_idx,
            bump: ctx.bumps.perm_chunk,
            entries: Vec::new(),
        };
        let mut data = chunk_info.try_borrow_mut_data()?;
        init_chunk.try_serialize(&mut &mut data[..])?;
    }

    // Deserialize the current chunk state.
    let mut chunk = {
        let data = chunk_info.try_borrow_data()?;
        PermChunk::try_deserialize(&mut &data[..])?
    };

    // Grow the account to fit the new entry.
    let current_len = chunk_info.data_len();
    let new_space = current_len + entry_size;
    let rent = Rent::get()?;
    let new_min = rent.minimum_balance(new_space);
    let current_lamports = chunk_info.lamports();
    if current_lamports < new_min {
        let diff = new_min - current_lamports;
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: chunk_info.clone(),
                },
            ),
            diff,
        )?;
    }
    chunk_info.resize(new_space)?;

    // Push the new entry and serialize back.
    chunk.entries.push(new_entry);
    {
        let mut data = chunk_info.try_borrow_mut_data()?;
        chunk.try_serialize(&mut &mut data[..])?;
    }

    emit!(PermissionCreated {
        organization: ctx.accounts.organization.key(),
        perm_index,
        name: name.clone(),
    });

    msg!("Permission '{}' created at index {}", name, perm_index);
    Ok(())
}
