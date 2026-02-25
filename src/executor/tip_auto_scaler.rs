use alloy::primitives::Address;
use std::collections::HashMap;

/// Rolling "contested target" hint cache for tip auto-scaling.
///
/// We only learn "competition present" after bundle submission (from builder hints).
/// This cache lets the *next* attempt for the same target outbid by `p75 + 1 wei`
/// when still profitable.
pub const DEFAULT_CONTESTED_TTL_BLOCKS: u64 = 8;

#[derive(Debug, Clone)]
pub struct ContestedTipCache {
    ttl_blocks: u64,
    contested_until_block: HashMap<Address, u64>,
}

impl Default for ContestedTipCache {
    fn default() -> Self {
        Self::new(DEFAULT_CONTESTED_TTL_BLOCKS)
    }
}

impl ContestedTipCache {
    pub fn new(ttl_blocks: u64) -> Self {
        Self {
            ttl_blocks: ttl_blocks.max(1),
            contested_until_block: HashMap::new(),
        }
    }

    pub fn is_contested(&mut self, target: Address, current_block: u64) -> bool {
        if current_block == 0 {
            return false;
        }
        self.prune(current_block);
        self.contested_until_block
            .get(&target)
            .copied()
            .unwrap_or(0)
            >= current_block
    }

    pub fn mark_contested(&mut self, target: Address, current_block: u64) {
        if current_block == 0 {
            return;
        }
        let until = current_block.saturating_add(self.ttl_blocks);
        self.contested_until_block.insert(target, until);
    }

    fn prune(&mut self, current_block: u64) {
        self.contested_until_block
            .retain(|_, until| *until >= current_block);
    }
}
