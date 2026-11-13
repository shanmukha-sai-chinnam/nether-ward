use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Configuration parameters for the Adaptive Rate Governor and Token Bucket
#[derive(Debug, Clone)]
pub struct RateGovernorConfig {
    /// Maximum burst capacity in tokens
    pub capacity: f64,
    /// Baseline target refill rate in tokens per second
    pub refill_rate: f64,
    /// Minimum allowed refill rate under heavy backoff
    pub min_refill_rate: f64,
    /// Initial backoff duration on HTTP 429
    pub initial_backoff: Duration,
    /// Maximum backoff ceiling
    pub max_backoff: Duration,
    /// Multiplicative decrease multiplier on throttle (0.0 to 1.0)
    pub decrease_factor: f64,
    /// Additive increase step on successful recovery (tokens/sec)
    pub increase_step: f64,
}

impl Default for RateGovernorConfig {
    fn default() -> Self {
        Self {
            capacity: 10.0,
            refill_rate: 5.0,
            min_refill_rate: 0.5,
            initial_backoff: Duration::from_millis(1500),
            max_backoff: Duration::from_secs(30),
            decrease_factor: 0.5,
            increase_step: 0.25,
        }
    }
}

#[derive(Debug)]
struct GovernorInner {
    available_tokens: f64,
    last_refill: Instant,
    current_refill_rate: f64,
    consecutive_throttles: u32,
    penalty_until: Option<Instant>,
    total_acquisitions: u64,
    total_throttles: u64,
}

/// Adaptive Rate Governor providing token bucket rate limiting, AIMD throttling, and Retry-After backoff
#[derive(Debug, Clone)]
pub struct RateGovernor {
    config: RateGovernorConfig,
    inner: Arc<Mutex<GovernorInner>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GovernorMetricsSnapshot {
    pub available_tokens: f64,
    pub current_refill_rate: f64,
    pub consecutive_throttles: u32,
    pub total_acquisitions: u64,
    pub total_throttles: u64,
    pub is_penalized: bool,
}

impl RateGovernor {
    pub fn new(config: RateGovernorConfig) -> Self {
        let initial_tokens = config.capacity;
        let initial_rate = config.refill_rate;
        Self {
            config,
            inner: Arc::new(Mutex::new(GovernorInner {
                available_tokens: initial_tokens,
                last_refill: Instant::now(),
                current_refill_rate: initial_rate,
                consecutive_throttles: 0,
                penalty_until: None,
                total_acquisitions: 0,
                total_throttles: 0,
            })),
        }
    }

    /// Calculate required wait time and consume tokens if immediately available
    pub async fn acquire(&self, tokens: f64) -> Duration {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        // 1. Check if we are in a penalty cool-down period from a previous 429
        let penalty_wait = if let Some(until) = inner.penalty_until {
            if until > now {
                until - now
            } else {
                inner.penalty_until = None;
                Duration::ZERO
            }
        } else {
            Duration::ZERO
        };

        // 2. Refill tokens based on elapsed time and current refill rate
        let elapsed = (now - inner.last_refill).as_secs_f64();
        inner.available_tokens = (inner.available_tokens + elapsed * inner.current_refill_rate)
            .min(self.config.capacity);
        inner.last_refill = now;

        // 3. Evaluate token availability
        if inner.available_tokens >= tokens && penalty_wait.is_zero() {
            inner.available_tokens -= tokens;
            inner.total_acquisitions += 1;
            Duration::ZERO
        } else {
            let deficit = (tokens - inner.available_tokens).max(0.0);
            let token_wait = if inner.current_refill_rate > 0.0 {
                Duration::from_secs_f64(deficit / inner.current_refill_rate)
            } else {
                self.config.initial_backoff
            };
            penalty_wait.max(token_wait)
        }
    }

    /// Cooperatively wait until tokens are available and acquired
    pub async fn acquire_async(&self, tokens: f64) {
        loop {
            let wait = self.acquire(tokens).await;
            if wait.is_zero() {
                break;
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// Record an upstream response status and headers to adaptively adjust quota pacing
    pub async fn record_response(
        &self,
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
    ) {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            inner.total_throttles += 1;
            inner.consecutive_throttles = inner.consecutive_throttles.saturating_add(1);

            // Multiplicative Decrease (AIMD)
            inner.current_refill_rate = (inner.current_refill_rate * self.config.decrease_factor)
                .max(self.config.min_refill_rate);

            // Calculate backoff duration
            let backoff = if let Some(retry_after) = Self::parse_retry_after(headers) {
                retry_after
            } else {
                let exp = 2u32.saturating_pow(inner.consecutive_throttles.saturating_sub(1));
                let base_ms = self.config.initial_backoff.as_millis() as u64;
                let calculated_ms = base_ms.saturating_mul(exp as u64);
                // Introduce pseudo-random decorrelated jitter (50ms - 250ms)
                let jitter_ms = (now.elapsed().subsec_nanos() % 200 + 50) as u64;
                Duration::from_millis(calculated_ms.saturating_add(jitter_ms))
                    .min(self.config.max_backoff)
            };

            inner.penalty_until = Some(now + backoff);
            // Drain bucket to prevent thundering herd immediately after throttle
            inner.available_tokens = 0.0;
        } else if status.is_success() {
            inner.consecutive_throttles = 0;
            // Additive Increase (AIMD)
            inner.current_refill_rate = (inner.current_refill_rate + self.config.increase_step)
                .min(self.config.refill_rate);
        }
    }

    /// Parse Retry-After or rate limit reset headers
    pub fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        // 1. Check standard Retry-After header
        if let Some(val) = headers.get(reqwest::header::RETRY_AFTER) {
            if let Ok(val_str) = val.to_str() {
                if let Ok(seconds) = val_str.trim().parse::<u64>() {
                    return Some(Duration::from_secs(seconds));
                }
                // Try parsing RFC 2822 / IMF-fixdate HTTP Date
                if let Ok(date) = chrono::DateTime::parse_from_rfc2822(val_str.trim()) {
                    let now = chrono::Utc::now();
                    let diff = date.with_timezone(&chrono::Utc) - now;
                    if let Ok(dur) = diff.to_std() {
                        return Some(dur);
                    }
                }
            }
        }

        // 2. Check X-RateLimit-Reset (epoch timestamp or seconds)
        if let Some(val) = headers.get("x-ratelimit-reset") {
            if let Ok(val_str) = val.to_str() {
                if let Ok(val_num) = val_str.trim().parse::<i64>() {
                    let now = chrono::Utc::now().timestamp();
                    if val_num > now {
                        return Some(Duration::from_secs((val_num - now) as u64));
                    } else if val_num > 0 && val_num < 3600 {
                        // Delta in seconds
                        return Some(Duration::from_secs(val_num as u64));
                    }
                }
            }
        }

        None
    }

    /// Snapshot current metrics for telemetry and monitoring
    pub async fn metrics(&self) -> GovernorMetricsSnapshot {
        let inner = self.inner.lock().await;
        let is_penalized = inner
            .penalty_until
            .map(|u| u > Instant::now())
            .unwrap_or(false);
        GovernorMetricsSnapshot {
            available_tokens: inner.available_tokens,
            current_refill_rate: inner.current_refill_rate,
            consecutive_throttles: inner.consecutive_throttles,
            total_acquisitions: inner.total_acquisitions,
            total_throttles: inner.total_throttles,
            is_penalized,
        }
    }
}

impl Default for RateGovernor {
    fn default() -> Self {
        Self::new(RateGovernorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_initial_capacity_and_acquire() {
        let config = RateGovernorConfig {
            capacity: 5.0,
            refill_rate: 10.0,
            ..Default::default()
        };
        let governor = RateGovernor::new(config);

        // Immediate acquire should succeed without delay
        let wait = governor.acquire(1.0).await;
        assert_eq!(wait, Duration::ZERO);

        let snap = governor.metrics().await;
        assert_eq!(snap.total_acquisitions, 1);
        assert!(snap.available_tokens <= 4.01 && snap.available_tokens >= 3.99);
    }

    #[tokio::test]
    async fn test_aimd_multiplicative_decrease_on_429() {
        let config = RateGovernorConfig {
            capacity: 10.0,
            refill_rate: 8.0,
            min_refill_rate: 1.0,
            decrease_factor: 0.5,
            ..Default::default()
        };
        let governor = RateGovernor::new(config);

        let headers = reqwest::header::HeaderMap::new();
        governor
            .record_response(reqwest::StatusCode::TOO_MANY_REQUESTS, &headers)
            .await;

        let snap = governor.metrics().await;
        assert_eq!(snap.total_throttles, 1);
        assert_eq!(snap.consecutive_throttles, 1);
        assert_eq!(snap.current_refill_rate, 4.0);
        assert!(snap.is_penalized);
    }

    #[tokio::test]
    async fn test_aimd_additive_increase_on_success() {
        let config = RateGovernorConfig {
            capacity: 10.0,
            refill_rate: 5.0,
            increase_step: 0.5,
            ..Default::default()
        };
        let governor = RateGovernor::new(config);

        // Simulate throttle then recovery
        let headers = reqwest::header::HeaderMap::new();
        governor
            .record_response(reqwest::StatusCode::TOO_MANY_REQUESTS, &headers)
            .await;

        let before_rate = governor.metrics().await.current_refill_rate;

        governor
            .record_response(reqwest::StatusCode::OK, &headers)
            .await;

        let after_rate = governor.metrics().await.current_refill_rate;
        assert!(after_rate > before_rate);
        assert_eq!(governor.metrics().await.consecutive_throttles, 0);
    }

    #[test]
    fn test_parse_retry_after_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "7".parse().unwrap());
        let dur = RateGovernor::parse_retry_after(&headers);
        assert_eq!(dur, Some(Duration::from_secs(7)));
    }

    #[test]
    fn test_parse_x_ratelimit_reset() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-reset", "15".parse().unwrap());
        let dur = RateGovernor::parse_retry_after(&headers);
        assert_eq!(dur, Some(Duration::from_secs(15)));
    }
}
