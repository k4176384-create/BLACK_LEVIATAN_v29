//! bl_crawler — K1 Rust Core: Token Bucket + Connection Stats
//! Autor: Luis Sánchez — BLACK LEVIATAN v29
//!
//! Expone funciones al Python layer vía PyO3:
//!   - TokenBucketRs: rate limiter de alta precisión
//!   - ConnectionStats: métricas de red en tiempo real

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Token Bucket de alta precisión implementado en Rust.
/// Mucho más preciso que el Python puro para >100 req/s.
#[pyclass]
struct TokenBucketRs {
    rate:     f64,
    capacity: f64,
    tokens:   f64,
    last:     Instant,
    lock:     Arc<Mutex<()>>,
}

#[pymethods]
impl TokenBucketRs {
    #[new]
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: Instant::now(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Consume `tokens` del bucket. Retorna segundos a esperar (0 si disponible).
    fn consume(&mut self, tokens: f64) -> f64 {
        let _guard = self.lock.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last = now;

        if self.tokens >= tokens {
            self.tokens -= tokens;
            0.0
        } else {
            let wait = (tokens - self.tokens) / self.rate;
            wait
        }
    }

    fn available_tokens(&self) -> f64 {
        self.tokens
    }
}

/// Estadísticas de conexión acumuladas (atómicas, thread-safe)
#[pyclass]
struct ConnectionStats {
    total_requests:   u64,
    success_count:    u64,
    error_count:      u64,
    total_bytes:      u64,
    total_latency_ms: f64,
}

#[pymethods]
impl ConnectionStats {
    #[new]
    fn new() -> Self {
        Self {
            total_requests:   0,
            success_count:    0,
            error_count:      0,
            total_bytes:      0,
            total_latency_ms: 0.0,
        }
    }

    fn record_success(&mut self, bytes: u64, latency_ms: f64) {
        self.total_requests   += 1;
        self.success_count    += 1;
        self.total_bytes      += bytes;
        self.total_latency_ms += latency_ms;
    }

    fn record_error(&mut self) {
        self.total_requests += 1;
        self.error_count    += 1;
    }

    fn avg_latency_ms(&self) -> f64 {
        if self.success_count == 0 { return 0.0; }
        self.total_latency_ms / self.success_count as f64
    }

    fn success_rate(&self) -> f64 {
        if self.total_requests == 0 { return 1.0; }
        self.success_count as f64 / self.total_requests as f64
    }

    fn to_dict(&self, py: Python<'_>) -> PyObject {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("total_requests",   self.total_requests).unwrap();
        dict.set_item("success_count",    self.success_count).unwrap();
        dict.set_item("error_count",      self.error_count).unwrap();
        dict.set_item("total_bytes",      self.total_bytes).unwrap();
        dict.set_item("avg_latency_ms",   self.avg_latency_ms()).unwrap();
        dict.set_item("success_rate",     self.success_rate()).unwrap();
        dict.into()
    }
}

#[pymodule]
fn bl_crawler(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TokenBucketRs>()?;
    m.add_class::<ConnectionStats>()?;
    Ok(())
}
