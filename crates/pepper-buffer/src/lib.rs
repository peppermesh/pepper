// SPDX-License-Identifier: Apache-2.0

//! Immutable, cheaply sliced byte ownership and hard byte budgets shared by
//! every Pepper data-plane product.

use bytes::{BufMut, Bytes, BytesMut};
use pepper_observability::{CostMetric, add_current_cost};
use std::{
    io::IoSlice,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    Crc32c(u32),
    Blake3([u8; 32]),
}

/// Immutable encoded bytes with an independently tracked logical length.
///
/// Cloning and slicing this value clone or slice `Bytes`; neither copies the
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBuffer {
    bytes: Bytes,
    logical_len: u64,
    checksum: Option<Checksum>,
}

impl OwnedBuffer {
    pub fn new(bytes: Bytes) -> Self {
        let logical_len = bytes.len() as u64;
        Self {
            bytes,
            logical_len,
            checksum: None,
        }
    }

    pub fn from_vec(bytes: Vec<u8>) -> Self {
        add_current_cost(CostMetric::OwnedBytes, bytes.len() as u64);
        Self::new(Bytes::from(bytes))
    }

    pub fn with_logical_len(mut self, logical_len: u64) -> Self {
        self.logical_len = logical_len;
        self
    }

    pub fn with_checksum(mut self, checksum: Checksum) -> Self {
        self.checksum = Some(checksum);
        self
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub fn checksum(&self) -> Option<Checksum> {
        self.checksum
    }

    pub fn slice(&self, range: std::ops::Range<usize>) -> Result<Self, BufferError> {
        if range.start > range.end || range.end > self.bytes.len() {
            return Err(BufferError::InvalidRange {
                start: range.start,
                end: range.end,
                length: self.bytes.len(),
            });
        }
        let encoded_len = self.bytes.len();
        let slice_len = range.end - range.start;
        let logical_len = if slice_len == encoded_len {
            self.logical_len
        } else {
            slice_len as u64
        };
        Ok(Self {
            bytes: self.bytes.slice(range),
            logical_len,
            checksum: None,
        })
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

impl From<Bytes> for OwnedBuffer {
    fn from(value: Bytes) -> Self {
        Self::new(value)
    }
}

/// Scatter/gather payload. Segment cloning and slicing remain zero-copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferChain {
    segments: Vec<OwnedBuffer>,
    encoded_len: usize,
    logical_len: u64,
}

impl BufferChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_buffer(buffer: OwnedBuffer) -> Self {
        let encoded_len = buffer.encoded_len();
        let logical_len = buffer.logical_len();
        Self {
            segments: vec![buffer],
            encoded_len,
            logical_len,
        }
    }

    pub fn from_segments(
        segments: impl IntoIterator<Item = OwnedBuffer>,
    ) -> Result<Self, BufferError> {
        let mut chain = Self::new();
        for segment in segments {
            chain.push(segment)?;
        }
        Ok(chain)
    }

    pub fn push(&mut self, segment: OwnedBuffer) -> Result<(), BufferError> {
        self.encoded_len = self
            .encoded_len
            .checked_add(segment.encoded_len())
            .ok_or(BufferError::LengthOverflow)?;
        self.logical_len = self
            .logical_len
            .checked_add(segment.logical_len())
            .ok_or(BufferError::LengthOverflow)?;
        self.segments.push(segment);
        Ok(())
    }

    pub fn segments(&self) -> &[OwnedBuffer] {
        &self.segments
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    pub fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub fn is_empty(&self) -> bool {
        self.encoded_len == 0
    }

    pub fn io_slices(&self) -> Vec<IoSlice<'_>> {
        self.segments
            .iter()
            .filter(|segment| !segment.bytes().is_empty())
            .map(|segment| IoSlice::new(segment.bytes()))
            .collect()
    }

    pub fn slice(&self, start: usize, end: usize) -> Result<Self, BufferError> {
        if start > end || end > self.encoded_len {
            return Err(BufferError::InvalidRange {
                start,
                end,
                length: self.encoded_len,
            });
        }
        let mut output = Self::new();
        let mut cursor = 0usize;
        for segment in &self.segments {
            let segment_end = cursor + segment.encoded_len();
            let overlap_start = start.max(cursor);
            let overlap_end = end.min(segment_end);
            if overlap_start < overlap_end {
                output.push(segment.slice((overlap_start - cursor)..(overlap_end - cursor))?)?;
            }
            cursor = segment_end;
            if cursor >= end {
                break;
            }
        }
        Ok(output)
    }

    /// Return the existing segment without allocating when possible; otherwise
    /// perform exactly one bounded payload allocation.
    pub fn coalesce(&self, maximum_bytes: usize) -> Result<OwnedBuffer, BufferError> {
        if self.encoded_len > maximum_bytes {
            return Err(BufferError::CoalesceLimit {
                bytes: self.encoded_len,
                maximum: maximum_bytes,
            });
        }
        if self.segments.len() == 1 {
            return Ok(self.segments[0].clone());
        }
        let mut bytes = BytesMut::with_capacity(self.encoded_len);
        for segment in &self.segments {
            bytes.put_slice(segment.bytes());
        }
        add_current_cost(CostMetric::OwnedBytes, self.encoded_len as u64);
        if self.segments.len() > 1 {
            add_current_cost(CostMetric::CopyOperations, 1);
            add_current_cost(CostMetric::CopyBytes, self.encoded_len as u64);
        }
        Ok(OwnedBuffer::new(bytes.freeze()).with_logical_len(self.logical_len))
    }
}

impl From<OwnedBuffer> for BufferChain {
    fn from(value: OwnedBuffer) -> Self {
        Self::from_buffer(value)
    }
}

/// An ordered batch keeps record boundaries without re-framing payload bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordBatch {
    records: Vec<BufferChain>,
    encoded_len: usize,
}

impl RecordBatch {
    pub fn push(&mut self, record: BufferChain) -> Result<(), BufferError> {
        self.encoded_len = self
            .encoded_len
            .checked_add(record.encoded_len())
            .ok_or(BufferError::LengthOverflow)?;
        self.records.push(record);
        Ok(())
    }

    pub fn records(&self) -> &[BufferChain] {
        &self.records
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BufferError {
    #[error("invalid buffer range {start}..{end} for length {length}")]
    InvalidRange {
        start: usize,
        end: usize,
        length: usize,
    },
    #[error("buffer length overflow")]
    LengthOverflow,
    #[error("coalescing {bytes} bytes exceeds the {maximum}-byte bound")]
    CoalesceLimit { bytes: usize, maximum: usize },
    #[error("request for {requested} bytes exceeds the {capacity}-byte budget")]
    RequestExceedsBudget { requested: usize, capacity: usize },
    #[error("the byte budget is closed")]
    BudgetClosed,
    #[error("the byte budget has insufficient capacity")]
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteBudgetSnapshot {
    pub capacity_bytes: u64,
    pub in_use_bytes: u64,
    pub high_water_bytes: u64,
    pub acquisitions: u64,
    pub rejections: u64,
    pub wait_microseconds: u64,
}

struct ByteBudgetInner {
    semaphore: Arc<Semaphore>,
    capacity: usize,
    in_use: AtomicU64,
    high_water: AtomicU64,
    acquisitions: AtomicU64,
    rejections: AtomicU64,
    wait_microseconds: AtomicU64,
}

#[derive(Clone)]
pub struct ByteBudget {
    inner: Arc<ByteBudgetInner>,
}

impl ByteBudget {
    pub fn new(capacity: usize) -> Result<Self, BufferError> {
        if capacity > Semaphore::MAX_PERMITS {
            return Err(BufferError::RequestExceedsBudget {
                requested: capacity,
                capacity: Semaphore::MAX_PERMITS,
            });
        }
        Ok(Self {
            inner: Arc::new(ByteBudgetInner {
                semaphore: Arc::new(Semaphore::new(capacity)),
                capacity,
                in_use: AtomicU64::new(0),
                high_water: AtomicU64::new(0),
                acquisitions: AtomicU64::new(0),
                rejections: AtomicU64::new(0),
                wait_microseconds: AtomicU64::new(0),
            }),
        })
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    pub async fn acquire(&self, bytes: usize) -> Result<ByteBudgetPermit, BufferError> {
        self.validate_request(bytes)?;
        let started = Instant::now();
        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_many_owned(bytes as u32)
            .await
            .map_err(|_| BufferError::BudgetClosed)?;
        self.inner.wait_microseconds.fetch_add(
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        Ok(self.finish_acquire(bytes, permit))
    }

    pub fn try_acquire(&self, bytes: usize) -> Result<ByteBudgetPermit, BufferError> {
        self.validate_request(bytes)?;
        match self
            .inner
            .semaphore
            .clone()
            .try_acquire_many_owned(bytes as u32)
        {
            Ok(permit) => Ok(self.finish_acquire(bytes, permit)),
            Err(TryAcquireError::NoPermits) => {
                self.inner.rejections.fetch_add(1, Ordering::Relaxed);
                Err(BufferError::BudgetExhausted)
            }
            Err(TryAcquireError::Closed) => Err(BufferError::BudgetClosed),
        }
    }

    pub fn snapshot(&self) -> ByteBudgetSnapshot {
        ByteBudgetSnapshot {
            capacity_bytes: self.inner.capacity as u64,
            in_use_bytes: self.inner.in_use.load(Ordering::Relaxed),
            high_water_bytes: self.inner.high_water.load(Ordering::Relaxed),
            acquisitions: self.inner.acquisitions.load(Ordering::Relaxed),
            rejections: self.inner.rejections.load(Ordering::Relaxed),
            wait_microseconds: self.inner.wait_microseconds.load(Ordering::Relaxed),
        }
    }

    fn validate_request(&self, bytes: usize) -> Result<(), BufferError> {
        if bytes > self.inner.capacity || bytes > u32::MAX as usize {
            return Err(BufferError::RequestExceedsBudget {
                requested: bytes,
                capacity: self.inner.capacity,
            });
        }
        Ok(())
    }

    fn finish_acquire(&self, bytes: usize, permit: OwnedSemaphorePermit) -> ByteBudgetPermit {
        self.inner.acquisitions.fetch_add(1, Ordering::Relaxed);
        let in_use = self
            .inner
            .in_use
            .fetch_add(bytes as u64, Ordering::AcqRel)
            .saturating_add(bytes as u64);
        self.inner.high_water.fetch_max(in_use, Ordering::Relaxed);
        ByteBudgetPermit {
            inner: Arc::clone(&self.inner),
            bytes,
            _permit: permit,
        }
    }
}

pub struct ByteBudgetPermit {
    inner: Arc<ByteBudgetInner>,
    bytes: usize,
    _permit: OwnedSemaphorePermit,
}

impl ByteBudgetPermit {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for ByteBudgetPermit {
    fn drop(&mut self) {
        self.inner
            .in_use
            .fetch_sub(self.bytes as u64, Ordering::AcqRel);
    }
}

struct AtomicByteBudgetInner {
    capacity: u64,
    in_use: AtomicU64,
    high_water: AtomicU64,
    acquisitions: AtomicU64,
    rejections: AtomicU64,
}

/// Lock-free, try-only byte admission for latency-sensitive paths that reject
/// instead of queueing when capacity is exhausted.
#[derive(Clone)]
pub struct AtomicByteBudget {
    inner: Arc<AtomicByteBudgetInner>,
}

impl AtomicByteBudget {
    pub fn new(capacity: usize) -> Result<Self, BufferError> {
        if capacity == 0 {
            return Err(BufferError::RequestExceedsBudget {
                requested: 0,
                capacity: 0,
            });
        }
        Ok(Self {
            inner: Arc::new(AtomicByteBudgetInner {
                capacity: capacity as u64,
                in_use: AtomicU64::new(0),
                high_water: AtomicU64::new(0),
                acquisitions: AtomicU64::new(0),
                rejections: AtomicU64::new(0),
            }),
        })
    }

    pub fn try_acquire(&self, bytes: usize) -> Result<AtomicByteBudgetPermit, BufferError> {
        let bytes = bytes as u64;
        if bytes > self.inner.capacity {
            self.inner.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(BufferError::RequestExceedsBudget {
                requested: bytes as usize,
                capacity: self.inner.capacity as usize,
            });
        }
        let mut current = self.inner.in_use.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                self.inner.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(BufferError::BudgetExhausted);
            };
            if next > self.inner.capacity {
                self.inner.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(BufferError::BudgetExhausted);
            }
            match self.inner.in_use.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.inner.acquisitions.fetch_add(1, Ordering::Relaxed);
                    self.inner.high_water.fetch_max(next, Ordering::Relaxed);
                    return Ok(AtomicByteBudgetPermit {
                        inner: Arc::clone(&self.inner),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub fn snapshot(&self) -> ByteBudgetSnapshot {
        ByteBudgetSnapshot {
            capacity_bytes: self.inner.capacity,
            in_use_bytes: self.inner.in_use.load(Ordering::Relaxed),
            high_water_bytes: self.inner.high_water.load(Ordering::Relaxed),
            acquisitions: self.inner.acquisitions.load(Ordering::Relaxed),
            rejections: self.inner.rejections.load(Ordering::Relaxed),
            wait_microseconds: 0,
        }
    }
}

pub struct AtomicByteBudgetPermit {
    inner: Arc<AtomicByteBudgetInner>,
    bytes: u64,
}

impl Drop for AtomicByteBudgetPermit {
    fn drop(&mut self) {
        self.inner.in_use.fetch_sub(self.bytes, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_slice_is_scatter_gather_and_coalesce_is_bounded() {
        let first = OwnedBuffer::new(Bytes::from_static(b"abcd"));
        let second = OwnedBuffer::new(Bytes::from_static(b"efgh"));
        let chain = BufferChain::from_segments([first, second]).unwrap();
        let sliced = chain.slice(2, 7).unwrap();
        assert_eq!(sliced.segment_count(), 2);
        assert_eq!(sliced.coalesce(5).unwrap().bytes(), b"cdefg".as_slice());
        assert_eq!(
            chain.coalesce(7).unwrap_err(),
            BufferError::CoalesceLimit {
                bytes: 8,
                maximum: 7
            }
        );
    }

    #[test]
    fn one_segment_coalesce_preserves_the_allocation() {
        let bytes = Bytes::from_static(b"one allocation");
        let pointer = bytes.as_ptr();
        let chain = BufferChain::from_buffer(OwnedBuffer::new(bytes));
        let coalesced = chain.coalesce(1024).unwrap();
        assert_eq!(coalesced.bytes().as_ptr(), pointer);
    }

    #[tokio::test]
    async fn byte_budget_is_hard_bounded_and_releases_capacity() {
        let budget = ByteBudget::new(10).unwrap();
        let first = budget.acquire(7).await.unwrap();
        assert!(matches!(
            budget.try_acquire(4),
            Err(BufferError::BudgetExhausted)
        ));
        assert_eq!(budget.snapshot().in_use_bytes, 7);
        drop(first);
        let second = budget.try_acquire(10).unwrap();
        assert_eq!(second.bytes(), 10);
        assert_eq!(budget.snapshot().high_water_bytes, 10);
    }

    #[test]
    fn atomic_byte_budget_rejects_without_queueing_and_releases() {
        let budget = AtomicByteBudget::new(100).unwrap();
        let first = budget.try_acquire(80).unwrap();
        assert!(matches!(
            budget.try_acquire(21),
            Err(BufferError::BudgetExhausted)
        ));
        assert_eq!(budget.snapshot().in_use_bytes, 80);
        drop(first);
        assert_eq!(budget.snapshot().in_use_bytes, 0);
        assert!(budget.try_acquire(100).is_ok());
    }
}
