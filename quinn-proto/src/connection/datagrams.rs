use std::{collections::VecDeque, mem, num::NonZeroU64};

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::{Connection, Event};
use crate::{
    TransportError,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.check_size(data.len())?;
        self.enqueue(data, drop, None)
    }

    /// Queue a datagram like [`send(data, true)`](Self::send), and report whether the peer
    /// acknowledges it
    ///
    /// The returned ID is later paired with the datagram's [`DatagramOutcome`] by
    /// [`poll_outcome`](Self::poll_outcome), signalled by `Event::DatagramOutcomes`. No outcome
    /// is reported for datagrams outstanding when the connection closes.
    ///
    /// Fails with [`SendAckTrackedError::TooManyTracked`] while
    /// [`TransportConfig::max_ack_tracked_datagrams`](crate::TransportConfig::max_ack_tracked_datagrams)
    /// tracked datagrams have no consumed outcome.
    pub fn send_ack_tracked(&mut self, data: Bytes) -> Result<DatagramId, SendAckTrackedError> {
        self.check_size(data.len())?;
        let state = &self.conn.datagrams;
        if state.outstanding_ack_tracked >= self.conn.config.max_ack_tracked_datagrams {
            return Err(SendAckTrackedError::TooManyTracked(data));
        }
        let id = DatagramId(NonZeroU64::MIN.saturating_add(state.last_ack_tracked_id));
        let drop = true;
        self.enqueue(data, drop, Some(id))?;
        let state = &mut self.conn.datagrams;
        state.last_ack_tracked_id = id.0.get();
        state.outstanding_ack_tracked += 1;
        Ok(id)
    }

    /// Take the next outcome of a datagram sent with [`send_ack_tracked`](Self::send_ack_tracked)
    pub fn poll_outcome(&mut self) -> Option<(DatagramId, DatagramOutcome)> {
        let state = &mut self.conn.datagrams;
        let outcome = state.outcomes.pop_front()?;
        state.outstanding_ack_tracked -= 1;
        Some(outcome)
    }

    fn check_size(&self, len: usize) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        let Some(max_buffer_payload) = send_buffer_size.checked_sub(size_of::<Datagram>()) else {
            return Err(SendDatagramError::TooLarge);
        };
        if len > Ord::min(max, max_buffer_payload) {
            return Err(SendDatagramError::TooLarge);
        }
        Ok(())
    }

    fn enqueue(
        &mut self,
        data: Bytes,
        drop: bool,
        id: Option<DatagramId>,
    ) -> Result<(), SendDatagramError> {
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        let state = &mut self.conn.datagrams;
        if drop {
            state.make_space_for(data.len(), send_buffer_size);
        } else if !state.has_send_buffer_space(data.len(), send_buffer_size) {
            state.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        state.outgoing.push_back(QueuedDatagram {
            frame: Datagram { data },
            id,
        });
        Ok(())
    }

    /// Discard queued datagrams that no longer fit the active path, waking blocked senders.
    pub(super) fn drop_oversized(&mut self) {
        let Some(max_datagram_size) = self.max_size() else {
            return;
        };
        if !self.conn.datagrams.drop_oversized(max_datagram_size)
            || !self.conn.datagrams.send_blocked
        {
            return;
        }

        self.conn.datagrams.send_blocked = false;
        self.conn.events.push_back(Event::DatagramsUnblocked);
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing.memory_used())
            .saturating_sub(size_of::<Datagram>())
    }
}

/// Identifies a datagram sent with [`Datagrams::send_ack_tracked`], unique within a connection
// `NonZeroU64` keeps `Option<DatagramId>` in every queued datagram at 8 bytes
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatagramId(NonZeroU64);

/// What happened to a datagram sent with [`Datagrams::send_ack_tracked`]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DatagramOutcome {
    /// The peer acknowledged a packet carrying the datagram
    ///
    /// Confirms receipt by the peer's QUIC stack, not by the peer application, which may still
    /// miss it, e.g. if its datagram receive buffer overflows.
    Acked,
    /// A packet carrying the datagram was declared lost, or discarded along with 0-RTT data
    ///
    /// The peer may still have received it. A later acknowledgement is not reported.
    Lost,
    /// Discarded unsent: evicted from the send buffer by a newer datagram, or too large for the
    /// path MTU
    Dropped,
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramBuffer,
    pub(super) outgoing: DatagramBuffer,
    pub(super) send_blocked: bool,
    /// Outcomes of ack-tracked datagrams not yet taken by the application
    outcomes: VecDeque<(DatagramId, DatagramOutcome)>,
    /// Whether `outcomes` grew since `Event::DatagramOutcomes` was last emitted
    outcomes_event_pending: bool,
    /// Ack-tracked datagrams that are queued, in flight, or in `outcomes`
    outstanding_ack_tracked: usize,
    last_ack_tracked_id: u64,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        let size_with_overhead = datagram.data.len() + size_of::<Datagram>();

        if size_with_overhead > window {
            // A valid frame can still exceed the local memory budget because of queue metadata.
            debug!("dropping datagram exceeding receive memory budget");
            return Ok(false);
        }

        let was_empty = self.incoming.is_empty();
        while self.incoming.memory_used() + size_with_overhead > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.incoming.push_back(QueuedDatagram {
            frame: datagram,
            id: None,
        });
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            trace!(len = prev.frame.data.len(), "dropping outgoing datagram");
            self.resolve(prev.id.as_slice(), DatagramOutcome::Dropped);
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self
            .outgoing
            .memory_used()
            .checked_add(datagram_len)
            .and_then(|total| total.checked_add(size_of::<Datagram>()))
        else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        let mut dropped_ids = Vec::new();
        self.outgoing.queue.retain(|datagram| {
            let len = datagram.frame.data.len();
            let result = len <= max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    len, max_payload
                );
                self.outgoing.payload_bytes -= len;
                dropped_ids.extend(datagram.id);
                dropped_any = true;
            }
            result
        });
        self.resolve(&dropped_ids, DatagramOutcome::Dropped);
        dropped_any
    }

    /// Record `outcome` for the ack-tracked datagrams `ids`
    pub(super) fn resolve(&mut self, ids: &[DatagramId], outcome: DatagramOutcome) {
        if ids.is_empty() {
            return;
        }
        self.outcomes_event_pending = true;
        self.outcomes.extend(ids.iter().map(|&id| (id, outcome)));
    }

    /// Whether `Event::DatagramOutcomes` should be emitted, clearing the request
    pub(super) fn take_outcomes_event(&mut self) -> bool {
        mem::take(&mut self.outcomes_event_pending)
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing. The ID of a written ack-tracked datagram is appended to `ack_tracked`.
    pub(super) fn write(
        &mut self,
        buf: &mut Vec<u8>,
        max_size: usize,
        ack_tracked: &mut Vec<DatagramId>,
    ) -> bool {
        let Some(datagram) = self.outgoing.pop_front() else {
            return false;
        };

        if buf.len() + datagram.frame.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.frame.data.len(), "DATAGRAM");
        datagram.frame.encode(true, buf);
        ack_tracked.extend(datagram.id);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.frame.data;
        Some(x)
    }
}

pub(super) struct QueuedDatagram {
    frame: Datagram,
    /// Set if sent with [`Datagrams::send_ack_tracked`], `None` for incoming datagrams
    id: Option<DatagramId>,
}

#[derive(Default)]
pub(super) struct DatagramBuffer {
    queue: VecDeque<QueuedDatagram>,
    payload_bytes: usize,
}

impl DatagramBuffer {
    fn push_back(&mut self, datagram: QueuedDatagram) {
        self.payload_bytes += datagram.frame.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<QueuedDatagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.frame.data.len();
        Some(datagram)
    }

    fn push_front(&mut self, datagram: QueuedDatagram) {
        self.payload_bytes += datagram.frame.data.len();
        self.queue.push_front(datagram);
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<Datagram>())
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.queue
            .front()
            .is_some_and(|x| x.frame.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing(data: &'static [u8], id: Option<u64>) -> QueuedDatagram {
        QueuedDatagram {
            frame: Datagram {
                data: Bytes::from_static(data),
            },
            id: id.map(|id| DatagramId(NonZeroU64::new(id).expect("IDs start at 1"))),
        }
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(outgoing(&[0; 7], None));
        state.outgoing.push_back(outgoing(&[0; 2], None));
        state.make_space_for(4, 10 + 2 * size_of::<Datagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].frame.data.len(), 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.queue.push_back(outgoing(&[0], None));
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    #[test]
    fn make_space_for_accounts_for_empty_datagram_metadata() {
        let mut state = DatagramState::default();
        for _ in 0..2 {
            state.outgoing.push_back(outgoing(&[], None));
        }
        let window = 2 * size_of::<Datagram>();

        assert!(!state.has_send_buffer_space(0, window));
        state.make_space_for(0, window);
        assert_eq!(state.outgoing.queue.len(), 1);
        assert!(state.has_send_buffer_space(0, window));
        state.outgoing.push_back(outgoing(&[], None));
        assert_eq!(state.outgoing.memory_used(), window);
    }

    #[test]
    fn send_buffer_space_handles_metadata_overflow() {
        assert!(!DatagramState::default().has_send_buffer_space(usize::MAX, usize::MAX));
    }

    #[test]
    fn drop_oversized_keeps_datagrams_at_limit() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(outgoing(&[0; 10], None));
        state.outgoing.push_back(outgoing(&[0; 11], None));

        assert!(state.drop_oversized(10));

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].frame.data.len(), 10);
        assert_eq!(state.outgoing.payload_bytes, 10);
    }

    #[test]
    fn evicted_ack_tracked_datagrams_are_dropped() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(outgoing(&[0; 7], Some(1)));
        state.outgoing.push_back(outgoing(&[0; 2], None));
        state.outgoing.push_back(outgoing(&[0; 20], Some(2)));

        state.make_space_for(4, 22 + 3 * size_of::<Datagram>());
        assert!(state.drop_oversized(10));

        let dropped = [1, 2].map(|id| {
            let id = DatagramId(NonZeroU64::new(id).expect("IDs start at 1"));
            (id, DatagramOutcome::Dropped)
        });
        assert!(state.outcomes.iter().eq(&dropped));
        assert!(state.take_outcomes_event());
        assert!(!state.take_outcomes_event());
    }
}

/// Errors that can arise when sending an ack-tracked datagram
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendAckTrackedError {
    /// The datagram could not be queued
    #[error(transparent)]
    Send(#[from] SendDatagramError),
    /// Too many ack-tracked datagrams have no consumed outcome
    ///
    /// See [`TransportConfig::max_ack_tracked_datagrams`](crate::TransportConfig::max_ack_tracked_datagrams).
    /// Consume outcomes with [`Datagrams::poll_outcome`] before retrying.
    #[error("too many ack-tracked datagrams outstanding")]
    TooManyTracked(Bytes),
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
