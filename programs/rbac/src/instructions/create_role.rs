use anchor_lang::prelude::*;

use crate::errors::RbacError;
use crate::state::*;

#[derive(Accounts)]
pub struct CreateRole<'info> {
    /// The chunk that will hold this role. Created on first use, grown on each new role.
    /// PDA: ["role_chunk", org, (org.role_count / ROLES_PER_CHUNK)_le4]
    /// CHECK: PDA seeds verified. Initialized on first use and grown on each call in the handler.
    #[account(
        mut,
        seeds = [
            b"role_chunk",
            organization.key().as_ref(),
            &(organization.role_count / ROLES_PER_CHUNK as u32).to_le_bytes(),
        ],
        bump,
    )]
    pub role_chunk: UncheckedAccount<'info>,

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

pub fn handler(ctx: Context<CreateRole>, name: String, description: String) -> Result<()> {
    let org = &mut ctx.accounts.organization;
    require!(org.state == OrgState::Updating, RbacError::OrgNotInUpdateMode);
    require!(name.len() <= MAX_ROLE_NAME_LEN, RbacError::RoleNameTooLong);
    require!(description.len() <= MAX_ROLE_DESC_LEN, RbacError::RoleDescTooLong);

    let topo_index = org.role_count;
    let chunk_idx = topo_index / ROLES_PER_CHUNK as u32;

    // Ensure this chunk is not overfull (should never happen if clients follow protocol).
    let slot = topo_index as usize % ROLES_PER_CHUNK;
    require!(slot < ROLES_PER_CHUNK, RbacError::ChunkFull);

    org.role_count = topo_index.checked_add(1).unwrap();
    org.active_role_count = org.active_role_count.checked_add(1).unwrap();

    let new_entry = RoleEntry {
        topo_index,
        version: 0,
        name: name.clone(),
        description: description.clone(),
        direct_permissions: Vec::new(),
        effective_permissions: Vec::new(),
        children: Vec::new(),
        active: true,
    };
    let entry_size = new_entry.serialized_size();

    let chunk_info = ctx.accounts.role_chunk.to_account_info();

    // Create the account the first time this chunk index is used.
    if chunk_info.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(RoleChunk::BASE_SIZE);
        let chunk_idx_bytes = chunk_idx.to_le_bytes();
        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.authority.to_account_info(),
                    to: chunk_info.clone(),
                },
                &[&[
                    b"role_chunk",
                    ctx.accounts.organization.key().as_ref(),
                    &chunk_idx_bytes,
                    &[ctx.bumps.role_chunk],
                ]],
            ),
            lamports,
            RoleChunk::BASE_SIZE as u64,
            ctx.program_id,
        )?;
        let init_chunk = RoleChunk {
            organization: ctx.accounts.organization.key(),
            chunk_index: chunk_idx,
            bump: ctx.bumps.role_chunk,
            entries: Vec::new(),
        };
        let mut data = chunk_info.try_borrow_mut_data()?;
        init_chunk.try_serialize(&mut &mut data[..])?;
    }

    // Deserialize the current chunk state.
    let mut chunk = {
        let data = chunk_info.try_borrow_data()?;
        RoleChunk::try_deserialize(&mut &data[..])?
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

    emit!(RoleCreated {
        organization: ctx.accounts.organization.key(),
        topo_index,
        name: name.clone(),
    });

    msg!("Role '{}' created at topo_index {}", name, topo_index);
    Ok(())
}
