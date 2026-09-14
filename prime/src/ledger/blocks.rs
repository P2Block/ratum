use super::Ledger;
use super::split::Payout;
use ratum::bitcoin::HASH_SIZE;
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedBlock {
    pub found_at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub total: u64,
    pub settled_at: Option<u64>,
    pub entries: Vec<Payout>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationReading {
    pub checked_at: u64,
    pub confirmations: i64,
}

impl ConfirmationReading {
    pub fn on_best_chain(&self) -> bool {
        self.confirmations >= 0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FoundBlock {
    pub found_at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    pub finder: String,
    pub tag_secondary: String,
    pub network_difficulty: f64,
    pub cumulative_work: u128,
}

impl Ledger {
    pub fn record_block(&mut self, block: FoundBlock) -> io::Result<()> {
        if self.blocks.iter().any(|b| b.block_hash == block.block_hash) {
            return Ok(());
        }
        if let Some(store) = &self.store
            && !store.insert_block(&block)?
        {
            return Ok(());
        }
        self.blocks.push(block);
        Ok(())
    }

    pub fn blocks(&self) -> &[FoundBlock] {
        &self.blocks
    }

    pub fn confirmations(&self, hash: &[u8; HASH_SIZE]) -> Option<ConfirmationReading> {
        self.confirmations.get(hash).copied()
    }

    pub fn record_confirmations(
        &mut self,
        hash: [u8; HASH_SIZE],
        reading: ConfirmationReading,
    ) -> io::Result<Option<ConfirmationReading>> {
        if let Some(store) = &self.store {
            store.write_confirmations(&hash, &reading)?;
        }
        Ok(self.confirmations.insert(hash, reading))
    }

    pub fn record_owed(&mut self, owed: OwedBlock) -> io::Result<()> {
        if self.owed.iter().any(|o| o.block_hash == owed.block_hash) {
            return Ok(());
        }
        if let Some(store) = &self.store {
            store.write_owed(&owed)?;
        }
        self.owed.push(owed);
        Ok(())
    }

    pub fn owed(&self) -> &[OwedBlock] {
        &self.owed
    }

    pub fn settle_owed(
        &mut self,
        hash: &[u8; 32],
        settled_at: u64,
    ) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if self.owed[index].settled_at.is_some() {
            return Ok(Some(self.owed[index].clone()));
        }
        let mut owed = self.owed[index].clone();
        owed.settled_at = Some(settled_at.max(1));
        if let Some(store) = &self.store {
            store.write_owed(&owed)?;
        }
        self.owed[index] = owed.clone();
        Ok(Some(owed))
    }

    pub fn void_owed(&mut self, hash: &[u8; 32]) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if let Some(store) = &self.store {
            store.remove_owed(hash)?;
        }
        Ok(Some(self.owed.remove(index)))
    }
}
