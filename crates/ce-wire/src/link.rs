//! `Link<A>`: the client state machine every typed client shares (generated typed clients in
//! every language share this state machine). One connection to cell `A`, found by name, kept up:
//!
//! ```text
//!   Idle -> Finding -> Live <-> Stale          (Stale: connected, nothing arrived for `stale_after`)
//!              |        |
//!              v        v
//!         Reconnecting {attempt, wait_ms, why}  -> Finding again after the wait (1 s doubling to 20 s)
//!              |
//!              v
//!   Refused {why}  (gate, right, schema, unknown op: trying again cannot help)   Failed {why}  (max_attempts spent)
//! ```
//!
//! A UI reads the state from [`Link::states`] (a `watch` channel: the newest state, never a queue) and shows it as it
//! is; it never invents "connecting..." on its own. The same states, names and rules are in every generated SDK
//! (`ce-wire-gen`: py, ts, ts-web, swift runtimes), so a page in any language shows the same thing for the same fault.
use crate::{Api, Client, Refusal, Stream, WireError};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LinkState {
    Idle,
    /// Looking the cell up: this machine's door, net.find, the mesh peers, then a local start.
    Finding,
    /// Connected; for a follow, the stream is open. `since_ms`: unix ms of the connect.
    Live { since_ms: u64 },
    /// Connected but no item for `quiet_ms` (no heartbeat in ce-wire yet: quiet may be idle or a dead path).
    Stale { quiet_ms: u64 },
    /// The last try failed with `why`; the next starts after `wait_ms`.
    Reconnecting { attempt: u32, wait_ms: u64, why: String },
    /// The cell said no in a way a retry cannot change.
    Refused { why: String },
    /// `max_attempts` tries spent.
    Failed { why: String },
}

impl LinkState {
    /// One short line for a status bar, the same words in every language.
    pub fn line(&self) -> String {
        match self {
            LinkState::Idle => "idle".into(),
            LinkState::Finding => "finding the cell".into(),
            LinkState::Live { .. } => "live".into(),
            LinkState::Stale { quiet_ms } => format!("live, nothing for {} s", quiet_ms / 1000),
            LinkState::Reconnecting { attempt, wait_ms, why } => format!("reconnecting in {} s (try {attempt}): {why}", wait_ms.div_ceil(1000)),
            LinkState::Refused { why } => format!("refused: {why}"),
            LinkState::Failed { why } => format!("failed: {why}"),
        }
    }
}

/// Retry or stop: a refusal the caller cannot fix by waiting stops the link. A `SchemaAt` stops too: the connect
/// already spent its one waiting retry on a pending update.
pub fn retryable(e: &WireError) -> bool {
    !matches!(e, WireError::Refused(Refusal::Gate(_) | Refusal::Right(_) | Refusal::Schema { .. } | Refusal::SchemaAt { .. } | Refusal::UnknownOp(_)))
}

#[derive(Clone, Debug)]
pub struct LinkCfg {
    pub first_wait: Duration,
    pub max_wait: Duration,
    /// 0 = forever.
    pub max_attempts: u32,
    pub stale_after: Duration,
}

impl Default for LinkCfg {
    fn default() -> Self {
        LinkCfg { first_wait: Duration::from_secs(1), max_wait: Duration::from_secs(20), max_attempts: 0, stale_after: Duration::from_secs(30) }
    }
}

impl LinkCfg {
    /// The wait before try `attempt` (1-based): first_wait doubling, capped at max_wait.
    pub fn wait(&self, attempt: u32) -> Duration {
        let f = 1u32.checked_shl(attempt.saturating_sub(1).min(20)).unwrap_or(u32::MAX);
        self.first_wait.saturating_mul(f).min(self.max_wait)
    }
}

type Connect<A> = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Client<A>, WireError>> + Send>> + Send + Sync>;

pub struct Link<A: Api> {
    connect: Connect<A>,
    pub cfg: LinkCfg,
    tx: watch::Sender<LinkState>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl<A: Api> Link<A> {
    /// A link that connects with `connect` (tests, a fixed address).
    pub fn new<F, Fut>(connect: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Client<A>, WireError>> + Send + 'static,
    {
        Link { connect: Arc::new(move || Box::pin(connect())), cfg: LinkCfg::default(), tx: watch::channel(LinkState::Idle).0 }
    }

    /// A link that finds `A` by name with a fresh token per try (`token`: e.g. `|| ce_gate::self_proof::<A>(3600)`).
    pub fn by_name<T>(token: T) -> Self
    where
        T: Fn() -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        let token = Arc::new(token);
        Self::new(move || {
            let token = token.clone();
            async move { Client::<A>::by_name(token().map_err(WireError::Io)?).await }
        })
    }

    pub fn with(mut self, cfg: LinkCfg) -> Self {
        self.cfg = cfg;
        self
    }

    /// The newest state; `changed().await` wakes on each move.
    pub fn states(&self) -> watch::Receiver<LinkState> {
        self.tx.subscribe()
    }

    pub fn state(&self) -> LinkState {
        self.tx.borrow().clone()
    }

    fn set(&self, s: LinkState) {
        self.tx.send_replace(s);
    }

    /// Connect, retrying with backoff. Ok: a client and state Live. Err: the state is Refused or Failed.
    pub async fn connect(&self) -> Result<Client<A>, LinkState> {
        let mut attempt = 0u32;
        loop {
            self.set(LinkState::Finding);
            match (self.connect)().await {
                Ok(c) => {
                    self.set(LinkState::Live { since_ms: now_ms() });
                    return Ok(c);
                }
                Err(e) => attempt = self.after_error(attempt, e).await?,
            }
        }
    }

    /// The failure path shared by connect and follow: Refused, Failed, or wait and return the next attempt number.
    async fn after_error(&self, attempt: u32, e: WireError) -> Result<u32, LinkState> {
        let why = e.to_string();
        if !retryable(&e) {
            let s = LinkState::Refused { why };
            self.set(s.clone());
            return Err(s);
        }
        let attempt = attempt + 1;
        if self.cfg.max_attempts > 0 && attempt >= self.cfg.max_attempts {
            let s = LinkState::Failed { why: format!("{attempt} tries: {why}") };
            self.set(s.clone());
            return Err(s);
        }
        let wait = self.cfg.wait(attempt);
        self.set(LinkState::Reconnecting { attempt, wait_ms: wait.as_millis() as u64, why });
        tokio::time::sleep(wait).await;
        Ok(attempt)
    }

    /// Follow stream `S` forever: connect, subscribe with `req()` (called on every reconnect, so a cursor can resume),
    /// hand each item to `on`, mark Stale after `stale_after` of quiet, reconnect when the stream ends or breaks.
    /// Returns only on Refused or Failed.
    pub async fn follow<S, R, F>(&self, mut req: R, mut on: F) -> LinkState
    where
        S: Stream<Api = A>,
        R: FnMut() -> S::Req,
        F: FnMut(S::Item),
    {
        let mut attempt = 0u32;
        loop {
            let c = match self.connect().await {
                Ok(c) => c,
                Err(s) => return s,
            };
            let e = match c.subscribe::<S>(&req()) {
                Err(e) => e,
                Ok(mut sub) => loop {
                    match tokio::time::timeout(self.cfg.stale_after, sub.next()).await {
                        Err(_) => {
                            let q = match self.state() {
                                LinkState::Stale { quiet_ms } => quiet_ms,
                                _ => 0,
                            };
                            self.set(LinkState::Stale { quiet_ms: q + self.cfg.stale_after.as_millis() as u64 });
                        }
                        Ok(Some(Ok(item))) => {
                            if !matches!(self.state(), LinkState::Live { .. }) {
                                self.set(LinkState::Live { since_ms: now_ms() });
                            }
                            attempt = 0;
                            on(item);
                        }
                        Ok(Some(Err(e))) => break e,
                        Ok(None) => break WireError::Closed,
                    }
                },
            };
            match self.after_error(attempt, e).await {
                Ok(a) => attempt = a,
                Err(s) => return s,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap() {
        let c = LinkCfg::default();
        let w: Vec<u64> = (1..=7).map(|a| c.wait(a).as_secs()).collect();
        assert_eq!(w, vec![1, 2, 4, 8, 16, 20, 20]);
        assert_eq!(c.wait(400).as_secs(), 20);
    }

    #[test]
    fn refusals_that_waiting_cannot_fix_stop() {
        assert!(!retryable(&WireError::Refused(Refusal::Right("x:read".into()))));
        assert!(!retryable(&WireError::Refused(Refusal::Schema { ours: 1, theirs: 2, api: "x".into() })));
        assert!(retryable(&WireError::Refused(Refusal::NoCell("x".into()))));
        assert!(retryable(&WireError::Timeout) && retryable(&WireError::Closed));
    }

    #[test]
    fn states_serialize_with_a_tag_every_language_reads() {
        let s = serde_json::to_string(&LinkState::Reconnecting { attempt: 2, wait_ms: 2000, why: "Closed".into() }).unwrap();
        assert_eq!(s, r#"{"state":"reconnecting","attempt":2,"wait_ms":2000,"why":"Closed"}"#);
        assert_eq!(LinkState::Stale { quiet_ms: 31000 }.line(), "live, nothing for 31 s");
    }
}
