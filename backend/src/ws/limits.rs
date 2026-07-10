use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

pub const MAX_CONNECTIONS_GLOBAL: usize = 64;
pub const MAX_CONNECTIONS_PER_SESSION: usize = 4;
pub const MAX_CONNECTIONS_PER_SOURCE: usize = 16;

#[derive(Debug, Eq, PartialEq)]
pub enum WsConnectionLimit {
    Global,
    Session,
    Source,
}

#[derive(Default)]
struct ConnectionCounts {
    total: usize,
    by_session: HashMap<String, usize>,
    by_source: HashMap<IpAddr, usize>,
}

pub struct WsConnectionLimiter {
    counts: Mutex<ConnectionCounts>,
    global_limit: usize,
    session_limit: usize,
    source_limit: usize,
}

impl WsConnectionLimiter {
    pub fn new(global_limit: usize, session_limit: usize, source_limit: usize) -> Self {
        assert!(global_limit > 0 && session_limit > 0 && source_limit > 0);
        Self {
            counts: Mutex::new(ConnectionCounts::default()),
            global_limit,
            session_limit,
            source_limit,
        }
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        session_id: &str,
        source: IpAddr,
    ) -> Result<WsConnectionPermit, WsConnectionLimit> {
        let source = normalize_ip(source);
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if counts.total >= self.global_limit {
            return Err(WsConnectionLimit::Global);
        }
        if counts.by_session.get(session_id).copied().unwrap_or(0) >= self.session_limit {
            return Err(WsConnectionLimit::Session);
        }
        if counts.by_source.get(&source).copied().unwrap_or(0) >= self.source_limit {
            return Err(WsConnectionLimit::Source);
        }

        counts.total += 1;
        *counts.by_session.entry(session_id.to_string()).or_default() += 1;
        *counts.by_source.entry(source).or_default() += 1;
        Ok(WsConnectionPermit {
            limiter: self.clone(),
            session_id: session_id.to_string(),
            source,
        })
    }

    pub fn total(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .total
    }
}

pub struct WsConnectionPermit {
    limiter: Arc<WsConnectionLimiter>,
    session_id: String,
    source: IpAddr,
}

impl Drop for WsConnectionPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        counts.total = counts.total.saturating_sub(1);
        decrement_or_remove(&mut counts.by_session, &self.session_id);
        decrement_or_remove(&mut counts.by_source, &self.source);
    }
}

fn decrement_or_remove<Key>(counts: &mut HashMap<Key, usize>, key: &Key)
where
    Key: Eq + std::hash::Hash,
{
    if let Some(count) = counts.get_mut(key) {
        if *count <= 1 {
            counts.remove(key);
        } else {
            *count -= 1;
        }
    }
}

fn normalize_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        source => source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_session_limit_and_releases_permits() {
        let limiter = Arc::new(WsConnectionLimiter::new(10, 2, 10));
        let source = "192.0.2.1".parse().unwrap();
        let first = limiter.try_acquire("session-a", source).unwrap();
        let second = limiter.try_acquire("session-a", source).unwrap();
        assert_eq!(
            limiter.try_acquire("session-a", source).err(),
            Some(WsConnectionLimit::Session)
        );
        assert_eq!(limiter.total(), 2);

        drop(first);
        assert!(limiter.try_acquire("session-a", source).is_ok());
        drop(second);
    }

    #[test]
    fn enforces_source_limit_across_sessions_and_normalizes_mapped_ipv4() {
        let limiter = Arc::new(WsConnectionLimiter::new(10, 10, 2));
        let ipv4 = "192.0.2.1".parse().unwrap();
        let mapped = "::ffff:192.0.2.1".parse().unwrap();
        let _first = limiter.try_acquire("session-a", ipv4).unwrap();
        let _second = limiter.try_acquire("session-b", mapped).unwrap();
        assert_eq!(
            limiter.try_acquire("session-c", ipv4).err(),
            Some(WsConnectionLimit::Source)
        );
    }

    #[test]
    fn enforces_global_limit() {
        let limiter = Arc::new(WsConnectionLimiter::new(2, 2, 2));
        let _first = limiter
            .try_acquire("session-a", "192.0.2.1".parse().unwrap())
            .unwrap();
        let _second = limiter
            .try_acquire("session-b", "192.0.2.2".parse().unwrap())
            .unwrap();
        assert_eq!(
            limiter
                .try_acquire("session-c", "192.0.2.3".parse().unwrap())
                .err(),
            Some(WsConnectionLimit::Global)
        );
    }
}
