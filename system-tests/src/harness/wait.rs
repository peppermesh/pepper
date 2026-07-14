// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail};
use std::{
    future::Future,
    time::{Duration, Instant},
};

pub async fn eventually<T, F, Fut>(
    description: &str,
    timeout: Duration,
    interval: Duration,
    mut probe: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let started = Instant::now();
    let mut attempts = 0u64;
    let mut last_error = None;
    while started.elapsed() < timeout {
        attempts += 1;
        match probe().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(interval).await;
    }
    bail!(
        "timed out after {:.3}s and {attempts} attempts waiting for {description}{}",
        started.elapsed().as_secs_f64(),
        last_error.map_or_else(String::new, |error| format!("; last error: {error}"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn waits_for_a_condition_without_fixed_completion_sleep() {
        let count = AtomicUsize::new(0);
        let value = eventually(
            "counter",
            Duration::from_secs(1),
            Duration::from_millis(1),
            || async {
                let next = count.fetch_add(1, Ordering::Relaxed);
                Ok((next >= 2).then_some(next))
            },
        )
        .await
        .unwrap();
        assert!(value >= 2);
    }
}
