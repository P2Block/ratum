use super::{IdentityWork, Ledger};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub identity: String,
    pub sats: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicGatewayFee {
    pub fee_bps: u16,
    pub subsidy_bps: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicGatewayFeeWork {
    pub public_gateway_work: u128,
    pub fee_work: u128,
    pub reassigned_work: u128,
    pub own_gateway_work: u128,
}

fn basis_points_of(work: u128, bps: u16) -> u128 {
    work.saturating_mul(u128::from(bps)) / u128::from(ratum::BASIS_POINTS_PER_UNIT)
}

impl Ledger {
    pub fn public_gateway_fee_work(&self, fee: PublicGatewayFee) -> PublicGatewayFeeWork {
        let mut public_gateway_work = 0u128;
        let mut fee_work = 0u128;
        for (identity, work) in &self.work_per_identity {
            let public = work - self.own_gateway_work_of(identity);
            public_gateway_work += public;
            fee_work += basis_points_of(public, fee.fee_bps);
        }
        let own_gateway_work: u128 = self.own_gateway_work_per_identity.values().sum();
        let reassigned_work =
            if own_gateway_work == 0 { 0 } else { basis_points_of(fee_work, fee.subsidy_bps) };
        PublicGatewayFeeWork { public_gateway_work, fee_work, reassigned_work, own_gateway_work }
    }

    fn weights_with_public_gateway_fee(&self, fee: PublicGatewayFee) -> (Vec<IdentityWork>, u128) {
        let PublicGatewayFeeWork { fee_work, reassigned_work, own_gateway_work, .. } =
            self.public_gateway_fee_work(fee);
        let mut given = 0u128;
        let mut weights = Vec::with_capacity(self.work_per_identity.len());
        for (identity, work) in &self.work_per_identity {
            let own = self.own_gateway_work_of(identity);
            let charged = basis_points_of(work - own, fee.fee_bps);
            let extra =
                reassigned_work.saturating_mul(own).checked_div(own_gateway_work).unwrap_or(0);
            given += extra;
            weights.push(IdentityWork { identity: identity.clone(), work: work - charged + extra });
        }
        weights.sort_by(|a, b| b.work.cmp(&a.work).then_with(|| a.identity.cmp(&b.identity)));
        (weights, fee_work.saturating_sub(given))
    }

    pub fn split(
        &self,
        value: u64,
        min_payout: u64,
        max_outputs: usize,
        fee: Option<PublicGatewayFee>,
    ) -> Vec<Payout> {
        if self.total_work == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        let (mut kept, retained_by_pool) = match fee {
            Some(f) if f.fee_bps > 0 => self.weights_with_public_gateway_fee(f),
            _ => (self.work_by_identity(), 0),
        };
        kept.truncate(max_outputs);
        let mut work: u128 = kept.iter().map(|w| w.work).sum::<u128>() + retained_by_pool;

        while let Some(w) = kept.last().map(|w| w.work) {
            if work == 0 {
                kept.clear();
                break;
            }
            if u128::from(value).saturating_mul(w) / work >= u128::from(min_payout) {
                break;
            }
            work -= w;
            kept.pop();
        }

        let mut left = value;
        let mut out = Vec::with_capacity(kept.len());
        for IdentityWork { identity, work: w } in kept {
            if work == 0 {
                break;
            }
            let amount = (u128::from(left).saturating_mul(w) / work) as u64;
            left -= amount;
            work -= w;
            if amount != 0 {
                out.push(Payout { identity, sats: amount });
            }
        }
        out
    }
}
