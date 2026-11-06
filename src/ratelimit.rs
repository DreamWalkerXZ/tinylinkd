use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Link creations allowed per User within [`LINK_CREATION_WINDOW`].
pub const LINK_CREATION_LIMIT: usize = 30;

/// The sliding window for [`LINK_CREATION_LIMIT`].
pub const LINK_CREATION_WINDOW: Duration = Duration::from_secs(60);

/// API requests allowed per API token within [`API_REQUEST_WINDOW`].
pub const API_REQUEST_LIMIT: usize = 120;

/// The sliding window for [`API_REQUEST_LIMIT`].
pub const API_REQUEST_WINDOW: Duration = Duration::from_secs(60);

/// A process-local sliding-window rate limiter keyed by an arbitrary value.
///
/// Each key remembers the instants of its recent events. An event older than
/// the window no longer counts, so the limit applies to any `window`-sized
/// interval ending now. State is in memory only and disappears on restart.
pub struct RateLimiter<K> {
    limit: usize,
    window: Duration,
    entries: Mutex<HashMap<K, VecDeque<Instant>>>,
}

impl<K> std::fmt::Debug for RateLimiter<K> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RateLimiter")
            .field("limit", &self.limit)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<K, VecDeque<Instant>>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn prune(now: Instant, window: Duration, times: &mut VecDeque<Instant>) {
        while times
            .front()
            .is_some_and(|oldest| now.duration_since(*oldest) >= window)
        {
            times.pop_front();
        }
    }

    fn retry_after(now: Instant, window: Duration, times: &VecDeque<Instant>) -> u64 {
        let oldest = *times.front().expect("a limited entry has events");
        window
            .saturating_sub(now.duration_since(oldest))
            .as_secs()
            .max(1)
    }

    /// When the key has reached the limit, returns the seconds to advertise
    /// in `Retry-After`. Recording is left to the caller.
    pub fn check(&self, key: &K) -> Option<u64> {
        let now = Instant::now();
        let mut entries = self.lock();
        let times = entries.get_mut(key)?;
        Self::prune(now, self.window, times);
        if times.len() < self.limit {
            return None;
        }
        Some(Self::retry_after(now, self.window, times))
    }

    /// Record one event for the key. Old entries elsewhere are pruned so the
    /// map does not grow without bound.
    pub fn record(&self, key: &K) {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|_, times| {
            Self::prune(now, self.window, times);
            !times.is_empty()
        });
        entries.entry(key.clone()).or_default().push_back(now);
    }

    /// Check the key and record the event when it is allowed. Returns the
    /// seconds to advertise in `Retry-After` when the request is limited.
    pub fn check_and_record(&self, key: &K) -> Option<u64> {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|_, times| {
            Self::prune(now, self.window, times);
            !times.is_empty()
        });
        if let Some(times) = entries.get(key) {
            if times.len() >= self.limit {
                return Some(Self::retry_after(now, self.window, times));
            }
        }
        entries.entry(key.clone()).or_default().push_back(now);
        None
    }
}
