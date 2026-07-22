// SPDX-License-Identifier: Apache-2.0

use pepper_config::{ErasureTransferConfig, ErasureTransferStrategy};
use std::{
    array, fmt,
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PLAN_COUNT: usize = 4;
const TARGET_SLOT_COUNT: usize = 64;
const EWMA_SCALE: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EcTransferPlan {
    GatewayFanout = 0,
    DistributedParity = 1,
    Hierarchical = 2,
    Pipelined = 3,
}

impl EcTransferPlan {
    pub(crate) const ALL: [Self; PLAN_COUNT] = [
        Self::GatewayFanout,
        Self::DistributedParity,
        Self::Hierarchical,
        Self::Pipelined,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayFanout => "gateway-fanout",
            Self::DistributedParity => "distributed-parity",
            Self::Hierarchical => "hierarchical",
            Self::Pipelined => "pipelined",
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::DistributedParity,
            2 => Self::Hierarchical,
            3 => Self::Pipelined,
            _ => Self::GatewayFanout,
        }
    }
}

impl fmt::Display for EcTransferPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn forced_plan(value: ErasureTransferStrategy) -> Option<EcTransferPlan> {
    match value {
        ErasureTransferStrategy::Adaptive => None,
        ErasureTransferStrategy::GatewayFanout => Some(EcTransferPlan::GatewayFanout),
        ErasureTransferStrategy::DistributedParity => Some(EcTransferPlan::DistributedParity),
        ErasureTransferStrategy::Hierarchical => Some(EcTransferPlan::Hierarchical),
        ErasureTransferStrategy::Pipelined => Some(EcTransferPlan::Pipelined),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EcPlannerInputs {
    pub logical_bytes: u64,
    pub encoded_bytes: u64,
    pub failure_domains: usize,
    pub active_bulk_streams: usize,
    pub bulk_stream_capacity: usize,
    pub bulk_stream_queue_micros: u64,
    pub write_queue_pressure_milli: u16,
    pub target_queue_pressure_milli: u16,
    pub active_encoders: usize,
    pub encoder_capacity: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct EcPlanDecision {
    pub plan: EcTransferPlan,
    pub candidate: EcTransferPlan,
    pub reasons: String,
    pub estimated_gateway_pressure_milli: u16,
    pub encoded_ratio_milli: u16,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EcPlanMetric {
    pub selected: u64,
    pub completed: u64,
    pub failures: u64,
    pub fallback: u64,
    pub completion_microseconds: u64,
    pub logical_bytes: u64,
    pub gateway_bytes: u64,
    pub internal_bytes: u64,
    pub cross_domain_bytes: u64,
}

pub(crate) struct ErasurePlanner {
    config: ErasureTransferConfig,
    current: AtomicU8,
    pending: AtomicU8,
    pending_samples: AtomicU64,
    last_switch_millis: AtomicU64,
    active_encoders: AtomicU64,
    active: [AtomicU64; PLAN_COUNT],
    selected: [AtomicU64; PLAN_COUNT],
    completed: [AtomicU64; PLAN_COUNT],
    failures: [AtomicU64; PLAN_COUNT],
    fallback: [AtomicU64; PLAN_COUNT],
    completion_microseconds: [AtomicU64; PLAN_COUNT],
    completion_ewma_microseconds: [AtomicU64; PLAN_COUNT],
    logical_bytes: [AtomicU64; PLAN_COUNT],
    gateway_bytes: [AtomicU64; PLAN_COUNT],
    internal_bytes: [AtomicU64; PLAN_COUNT],
    cross_domain_bytes: [AtomicU64; PLAN_COUNT],
    target_active: [AtomicU64; TARGET_SLOT_COUNT],
    target_completion_ewma_microseconds: [AtomicU64; TARGET_SLOT_COUNT],
    target_failure_ewma_milli: [AtomicU64; TARGET_SLOT_COUNT],
}

impl ErasurePlanner {
    pub(crate) fn new(config: ErasureTransferConfig) -> Self {
        Self {
            config,
            current: AtomicU8::new(EcTransferPlan::GatewayFanout as u8),
            pending: AtomicU8::new(EcTransferPlan::GatewayFanout as u8),
            pending_samples: AtomicU64::new(0),
            last_switch_millis: AtomicU64::new(0),
            active_encoders: AtomicU64::new(0),
            active: array::from_fn(|_| AtomicU64::new(0)),
            selected: array::from_fn(|_| AtomicU64::new(0)),
            completed: array::from_fn(|_| AtomicU64::new(0)),
            failures: array::from_fn(|_| AtomicU64::new(0)),
            fallback: array::from_fn(|_| AtomicU64::new(0)),
            completion_microseconds: array::from_fn(|_| AtomicU64::new(0)),
            completion_ewma_microseconds: array::from_fn(|_| AtomicU64::new(0)),
            logical_bytes: array::from_fn(|_| AtomicU64::new(0)),
            gateway_bytes: array::from_fn(|_| AtomicU64::new(0)),
            internal_bytes: array::from_fn(|_| AtomicU64::new(0)),
            cross_domain_bytes: array::from_fn(|_| AtomicU64::new(0)),
            target_active: array::from_fn(|_| AtomicU64::new(0)),
            target_completion_ewma_microseconds: array::from_fn(|_| AtomicU64::new(0)),
            target_failure_ewma_milli: array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub(crate) fn pipeline_max_hops(&self) -> usize {
        usize::from(self.config.pipeline_max_hops)
    }

    pub(crate) fn target_pressure_milli<'a>(
        &self,
        node_ids: impl IntoIterator<Item = &'a str>,
        capacity_per_target: usize,
    ) -> u16 {
        node_ids
            .into_iter()
            .map(|node_id| {
                let slot = target_slot(node_id);
                let active = self.target_active[slot].load(Ordering::Relaxed);
                let occupancy = active
                    .saturating_mul(1_000)
                    .checked_div(capacity_per_target.max(1) as u64)
                    .unwrap_or(1_000)
                    .min(1_000);
                occupancy.max(
                    self.target_failure_ewma_milli[slot]
                        .load(Ordering::Relaxed)
                        .min(1_000),
                ) as u16
            })
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn target_guard<'a>(&'a self, node_id: &str) -> TargetGuard<'a> {
        let slot = target_slot(node_id);
        self.target_active[slot].fetch_add(1, Ordering::Relaxed);
        TargetGuard {
            planner: self,
            slot,
            failed: true,
            started: Instant::now(),
        }
    }

    pub(crate) fn encoding_guard(&self) -> EncodingGuard<'_> {
        self.active_encoders.fetch_add(1, Ordering::Relaxed);
        EncodingGuard { planner: self }
    }

    pub(crate) fn select(&self, mut inputs: EcPlannerInputs) -> EcPlanDecision {
        inputs.active_encoders = inputs
            .active_encoders
            .max(self.active_encoders.load(Ordering::Relaxed) as usize);
        let ratio_milli = if inputs.logical_bytes == 0 {
            1_000
        } else {
            inputs
                .encoded_bytes
                .saturating_mul(1_000)
                .checked_div(inputs.logical_bytes)
                .unwrap_or(1_000)
                .min(u64::from(u16::MAX)) as u16
        };
        let gateway_pressure = self.gateway_pressure_milli(&inputs);
        let cpu_pressure = if inputs.encoder_capacity == 0 {
            0
        } else {
            inputs
                .active_encoders
                .saturating_mul(1_000)
                .checked_div(inputs.encoder_capacity)
                .unwrap_or(1_000)
                .min(1_000) as u16
        };
        let transport_queue_pressure = inputs
            .bulk_stream_queue_micros
            .saturating_mul(1_000)
            .checked_div(10_000)
            .unwrap_or(1_000)
            .min(1_000) as u16;
        let (candidate, primary_reason) =
            if inputs.encoded_bytes < self.config.minimum_adaptive_stripe_bytes {
                (EcTransferPlan::GatewayFanout, "small-stripe")
            } else if ratio_milli <= 350 {
                (EcTransferPlan::GatewayFanout, "compression-reduced-egress")
            } else if inputs.target_queue_pressure_milli >= 900 {
                // A pipeline concentrates success on every hop and
                // hierarchical/distributed plans concentrate work on a
                // coordinator. Direct fanout is the conservative choice when
                // a durable target is failing or saturated.
                (
                    EcTransferPlan::GatewayFanout,
                    "target-pressure-direct-fallback",
                )
            } else if transport_queue_pressure >= 900 && inputs.bulk_stream_capacity <= 2 {
                // A bounded chain spreads internal egress across owners. It
                // is reserved for an actually narrow stream-admission lane.
                // On ordinary multi-stream links the measured plan matrix
                // shows that its 6.5x internal traffic loses to parallel
                // fanout or distributed parity even when queue delay spikes.
                (
                    EcTransferPlan::Pipelined,
                    "narrow-bulk-stream-lane-saturated",
                )
            } else if gateway_pressure >= 950
                || inputs.write_queue_pressure_milli >= 900
                || cpu_pressure >= 850
            {
                (
                    EcTransferPlan::DistributedParity,
                    "gateway-bandwidth-or-codec-saturated",
                )
            } else if gateway_pressure >= 850 && inputs.failure_domains >= 3 {
                (EcTransferPlan::Hierarchical, "cross-domain-egress-pressure")
            } else if gateway_pressure >= 850 || cpu_pressure >= 700 {
                (
                    EcTransferPlan::DistributedParity,
                    "gateway-or-codec-pressure",
                )
            } else {
                (EcTransferPlan::GatewayFanout, "direct-path-headroom")
            };

        let forced = forced_plan(self.config.strategy);
        let selected = forced.unwrap_or_else(|| self.apply_hysteresis(candidate));
        self.selected[selected.index()].fetch_add(1, Ordering::Relaxed);
        EcPlanDecision {
            plan: selected,
            candidate,
            reasons: if forced.is_some() {
                format!("forced:{}", selected.as_str())
            } else if selected == candidate {
                primary_reason.to_string()
            } else {
                format!(
                    "hysteresis:{};candidate:{primary_reason}",
                    selected.as_str()
                )
            },
            estimated_gateway_pressure_milli: gateway_pressure,
            encoded_ratio_milli: ratio_milli,
        }
    }

    fn gateway_pressure_milli(&self, inputs: &EcPlannerInputs) -> u16 {
        let stream_pressure = if inputs.bulk_stream_capacity == 0 {
            0
        } else {
            inputs
                .active_bulk_streams
                .saturating_mul(1_000)
                .checked_div(inputs.bulk_stream_capacity)
                .unwrap_or(1_000)
                .min(1_000) as u16
        };
        if self.config.gateway_capacity_mbps == 0 {
            return stream_pressure;
        }
        // Estimate the pressure that *direct fanout* would create. Using the
        // current plan's completion time creates a closed-loop oscillation:
        // a slower pipeline lowers its own observed request rate, makes the
        // gateway appear idle, and immediately selects fanout again. The
        // direct-path EWMA plus activity across every plan predicts the load
        // we would restore by switching back.
        let observed_completion_micros = self.completion_ewma_microseconds
            [EcTransferPlan::GatewayFanout.index()]
        .load(Ordering::Relaxed);
        // Before the first direct completion, use a conservative one-second
        // service-time estimate. The old 100 ms seed made a 10/25/100 Gb/s
        // gateway look saturated during startup and switched away from the
        // faster direct path before any measurement existed.
        let completion_micros = if observed_completion_micros == 0 {
            1_000_000
        } else {
            observed_completion_micros.max(100_000)
        };
        let active = self
            .active
            .iter()
            .map(|active| active.load(Ordering::Relaxed))
            .sum::<u64>()
            .saturating_add(1)
            .max(inputs.active_encoders.max(1) as u64);
        let gateway_bytes = inputs.encoded_bytes.saturating_mul(3) / 2;
        let demand_bytes_per_second = gateway_bytes
            .saturating_mul(active)
            .saturating_mul(1_000_000)
            / completion_micros;
        let capacity_bytes_per_second =
            self.config.gateway_capacity_mbps.saturating_mul(1_000_000) / 8;
        demand_bytes_per_second
            .saturating_mul(1_000)
            .checked_div(capacity_bytes_per_second.max(1))
            .unwrap_or(1_000)
            .min(1_000) as u16
    }

    fn apply_hysteresis(&self, candidate: EcTransferPlan) -> EcTransferPlan {
        let current = EcTransferPlan::from_u8(self.current.load(Ordering::Acquire));
        if candidate == current {
            self.pending.store(candidate as u8, Ordering::Release);
            self.pending_samples.store(0, Ordering::Release);
            return current;
        }
        let previous_pending = self.pending.swap(candidate as u8, Ordering::AcqRel);
        let samples = if previous_pending == candidate as u8 {
            self.pending_samples.fetch_add(1, Ordering::AcqRel) + 1
        } else {
            self.pending_samples.store(1, Ordering::Release);
            1
        };
        let now = unix_millis();
        let dwell_complete = now.saturating_sub(self.last_switch_millis.load(Ordering::Acquire))
            >= self.config.minimum_dwell_ms;
        if samples >= u64::from(self.config.switch_after_samples) && dwell_complete {
            self.current.store(candidate as u8, Ordering::Release);
            self.last_switch_millis.store(now, Ordering::Release);
            self.pending_samples.store(0, Ordering::Release);
            candidate
        } else {
            current
        }
    }

    pub(crate) fn begin(&self, plan: EcTransferPlan, logical_bytes: u64) -> PlanGuard<'_> {
        self.active[plan.index()].fetch_add(1, Ordering::Relaxed);
        PlanGuard {
            planner: self,
            plan,
            logical_bytes,
            gateway_bytes: 0,
            internal_bytes: 0,
            cross_domain_bytes: 0,
            // A dropped future, timeout, early return, or transport error must
            // count as a failure. Callers explicitly mark the guard complete
            // only after every canonical shard acknowledgement is validated.
            failed: true,
            started: Instant::now(),
        }
    }

    pub(crate) fn record_fallback(&self, plan: EcTransferPlan) {
        self.fallback[plan.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn metrics(&self) -> [EcPlanMetric; PLAN_COUNT] {
        array::from_fn(|index| EcPlanMetric {
            selected: self.selected[index].load(Ordering::Relaxed),
            completed: self.completed[index].load(Ordering::Relaxed),
            failures: self.failures[index].load(Ordering::Relaxed),
            fallback: self.fallback[index].load(Ordering::Relaxed),
            completion_microseconds: self.completion_microseconds[index].load(Ordering::Relaxed),
            logical_bytes: self.logical_bytes[index].load(Ordering::Relaxed),
            gateway_bytes: self.gateway_bytes[index].load(Ordering::Relaxed),
            internal_bytes: self.internal_bytes[index].load(Ordering::Relaxed),
            cross_domain_bytes: self.cross_domain_bytes[index].load(Ordering::Relaxed),
        })
    }
}

fn target_slot(node_id: &str) -> usize {
    let digest = blake3::hash(node_id.as_bytes());
    usize::from(digest.as_bytes()[0]) % TARGET_SLOT_COUNT
}

pub(crate) struct TargetGuard<'a> {
    planner: &'a ErasurePlanner,
    slot: usize,
    failed: bool,
    started: Instant,
}

impl TargetGuard<'_> {
    pub(crate) fn complete(&mut self) {
        self.failed = false;
    }
}

impl Drop for TargetGuard<'_> {
    fn drop(&mut self) {
        self.planner.target_active[self.slot].fetch_sub(1, Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        update_ewma(
            &self.planner.target_completion_ewma_microseconds[self.slot],
            elapsed,
        );
        update_ewma(
            &self.planner.target_failure_ewma_milli[self.slot],
            if self.failed { 1_000 } else { 0 },
        );
    }
}

fn update_ewma(target: &AtomicU64, sample: u64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(if old == 0 {
            sample
        } else {
            old.saturating_mul(EWMA_SCALE - 1).saturating_add(sample) / EWMA_SCALE
        })
    });
}

pub(crate) struct EncodingGuard<'a> {
    planner: &'a ErasurePlanner,
}

impl Drop for EncodingGuard<'_> {
    fn drop(&mut self) {
        self.planner.active_encoders.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct PlanGuard<'a> {
    planner: &'a ErasurePlanner,
    plan: EcTransferPlan,
    logical_bytes: u64,
    gateway_bytes: u64,
    internal_bytes: u64,
    cross_domain_bytes: u64,
    failed: bool,
    started: Instant,
}

impl PlanGuard<'_> {
    pub(crate) fn add_gateway_bytes(&mut self, bytes: u64) {
        self.gateway_bytes = self.gateway_bytes.saturating_add(bytes);
    }

    pub(crate) fn add_internal_bytes(&mut self, bytes: u64) {
        self.internal_bytes = self.internal_bytes.saturating_add(bytes);
    }

    pub(crate) fn add_cross_domain_bytes(&mut self, bytes: u64) {
        self.cross_domain_bytes = self.cross_domain_bytes.saturating_add(bytes);
    }

    pub(crate) fn complete(&mut self) {
        self.failed = false;
    }
}

impl Drop for PlanGuard<'_> {
    fn drop(&mut self) {
        let index = self.plan.index();
        let elapsed = self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        self.planner.active[index].fetch_sub(1, Ordering::Relaxed);
        self.planner.logical_bytes[index].fetch_add(self.logical_bytes, Ordering::Relaxed);
        self.planner.gateway_bytes[index].fetch_add(self.gateway_bytes, Ordering::Relaxed);
        self.planner.internal_bytes[index].fetch_add(self.internal_bytes, Ordering::Relaxed);
        self.planner.cross_domain_bytes[index]
            .fetch_add(self.cross_domain_bytes, Ordering::Relaxed);
        self.planner.completion_microseconds[index].fetch_add(elapsed, Ordering::Relaxed);
        if self.failed {
            self.planner.failures[index].fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.planner.completed[index].fetch_add(1, Ordering::Relaxed);
        let _ = self.planner.completion_ewma_microseconds[index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |old| {
                Some(if old == 0 {
                    elapsed
                } else {
                    old.saturating_mul(EWMA_SCALE - 1).saturating_add(elapsed) / EWMA_SCALE
                })
            },
        );
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(capacity_mbps: u64) -> ErasureTransferConfig {
        ErasureTransferConfig {
            gateway_capacity_mbps: capacity_mbps,
            switch_after_samples: 1,
            minimum_dwell_ms: 0,
            minimum_adaptive_stripe_bytes: 1,
            ..ErasureTransferConfig::default()
        }
    }

    fn inputs(active: usize) -> EcPlannerInputs {
        EcPlannerInputs {
            logical_bytes: 24 * 1024 * 1024,
            encoded_bytes: 24 * 1024 * 1024,
            failure_domains: 9,
            active_bulk_streams: active,
            bulk_stream_capacity: 64,
            active_encoders: active,
            encoder_capacity: 32,
            ..EcPlannerInputs::default()
        }
    }

    #[test]
    fn adaptive_selector_moves_from_distributed_parity_to_direct_as_link_capacity_grows() {
        let one_gigabit = ErasurePlanner::new(config(1_000));
        let ten_gigabit = ErasurePlanner::new(config(10_000));
        let twenty_five_gigabit = ErasurePlanner::new(config(25_000));
        let hundred_gigabit = ErasurePlanner::new(config(100_000));

        assert_eq!(
            one_gigabit.select(inputs(8)).plan,
            EcTransferPlan::DistributedParity
        );
        assert_eq!(
            ten_gigabit.select(inputs(2)).plan,
            EcTransferPlan::GatewayFanout
        );
        assert_eq!(
            twenty_five_gigabit.select(inputs(1)).plan,
            EcTransferPlan::GatewayFanout
        );
        assert_eq!(
            hundred_gigabit.select(inputs(1)).plan,
            EcTransferPlan::GatewayFanout
        );

        let cross_rack = ErasurePlanner::new(config(1_000));
        assert_eq!(
            cross_rack.select(inputs(3)).plan,
            EcTransferPlan::Hierarchical
        );
    }

    #[test]
    fn compression_keeps_direct_fanout_even_under_gateway_pressure() {
        let planner = ErasurePlanner::new(config(1_000));
        let mut compressed = inputs(16);
        compressed.encoded_bytes = compressed.logical_bytes / 10;
        assert_eq!(
            planner.select(compressed).plan,
            EcTransferPlan::GatewayFanout
        );
    }

    #[test]
    fn hysteresis_requires_repeated_candidate_before_switching() {
        let mut cfg = config(1_000);
        cfg.switch_after_samples = 3;
        let planner = ErasurePlanner::new(cfg);
        assert_eq!(
            planner.select(inputs(8)).plan,
            EcTransferPlan::GatewayFanout
        );
        assert_eq!(
            planner.select(inputs(8)).plan,
            EcTransferPlan::GatewayFanout
        );
        assert_eq!(
            planner.select(inputs(8)).plan,
            EcTransferPlan::DistributedParity
        );
    }

    #[test]
    fn forced_plan_bypasses_adaptive_hysteresis() {
        let mut cfg = config(100_000);
        cfg.strategy = ErasureTransferStrategy::DistributedParity;
        let planner = ErasurePlanner::new(cfg);
        let decision = planner.select(inputs(1));
        assert_eq!(decision.plan, EcTransferPlan::DistributedParity);
        assert_eq!(decision.reasons, "forced:distributed-parity");
    }

    #[test]
    fn measured_queue_delay_drives_pipeline_and_target_failures_drive_direct_fallback() {
        let planner = ErasurePlanner::new(config(100_000));
        let mut queued = inputs(1);
        queued.bulk_stream_queue_micros = 20_000;
        queued.bulk_stream_capacity = 1;
        assert_eq!(planner.select(queued).plan, EcTransferPlan::Pipelined);

        let planner = ErasurePlanner::new(config(100_000));
        let mut parallel_queue = inputs(1);
        parallel_queue.bulk_stream_queue_micros = 20_000;
        assert_eq!(
            planner.select(parallel_queue).plan,
            EcTransferPlan::GatewayFanout
        );

        let planner = ErasurePlanner::new(config(100_000));
        drop(planner.target_guard("target-a"));
        let mut failed_target = inputs(1);
        failed_target.target_queue_pressure_milli = planner.target_pressure_milli(["target-a"], 8);
        assert_eq!(failed_target.target_queue_pressure_milli, 1_000);
        assert_eq!(
            planner.select(failed_target).plan,
            EcTransferPlan::GatewayFanout
        );
        assert_eq!(
            planner.select(failed_target).reasons,
            "target-pressure-direct-fallback"
        );
    }

    #[test]
    fn dropped_plan_guards_are_failures_and_only_validated_plans_complete() {
        let planner = ErasurePlanner::new(config(100_000));
        drop(planner.begin(EcTransferPlan::Hierarchical, 1024));
        let mut completed = planner.begin(EcTransferPlan::GatewayFanout, 2048);
        completed.add_gateway_bytes(1024);
        completed.add_internal_bytes(1536);
        completed.add_cross_domain_bytes(512);
        completed.complete();
        drop(completed);

        let metrics = planner.metrics();
        assert_eq!(metrics[EcTransferPlan::Hierarchical.index()].failures, 1);
        let direct = metrics[EcTransferPlan::GatewayFanout.index()];
        assert_eq!(direct.completed, 1);
        assert_eq!(direct.logical_bytes, 2048);
        assert_eq!(direct.gateway_bytes, 1024);
        assert_eq!(direct.internal_bytes, 1536);
        assert_eq!(direct.cross_domain_bytes, 512);
    }
}
