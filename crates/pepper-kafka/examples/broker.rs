// SPDX-License-Identifier: Apache-2.0

use pepper_kafka::{
    KafkaCluster,
    server::{KafkaServer, KafkaServerConfig},
};
use pepper_kafka_protocol::ProtocolLimits;
use std::{env, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_port = env::var("PEPPER_KAFKA_PORT")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(19092u16);
    let root = env::var_os("PEPPER_KAFKA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::temp_dir().join(format!("pepper-kafka-example-{}", std::process::id()))
        });
    let mut listeners = Vec::new();
    let mut brokers = Vec::new();
    for broker_id in 0..3 {
        let port = base_port
            .checked_add(broker_id)
            .ok_or("Kafka example port overflow")?;
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        brokers.push((i32::from(broker_id), "127.0.0.1".to_string(), port));
        listeners.push(listener);
    }
    let cluster = KafkaCluster::open(
        &root,
        "pepper-example",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await?;
    for (broker_id, listener) in listeners.into_iter().enumerate() {
        let server = Arc::new(KafkaServer::new(
            broker_id as i32,
            Arc::clone(&cluster),
            KafkaServerConfig::default(),
        )?);
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }
    println!(
        "{}",
        serde_json::json!({
            "status": "ready",
            "bootstrap": format!("127.0.0.1:{base_port}"),
            "root": root,
            "brokers": 3
        })
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}
