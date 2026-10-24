use crate::invocation::Gates;
use std::sync::Arc;

/// Shared axum state. Cheap to clone (all fields are `Arc`-backed).
#[derive(Clone)]
pub struct AppState {
    pub gates: Arc<Gates>,
}

impl AppState {
    pub fn new(gates: Gates) -> Self {
        Self { gates: Arc::new(gates) }
    }
}
