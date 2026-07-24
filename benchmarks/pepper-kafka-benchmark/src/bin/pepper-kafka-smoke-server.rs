// SPDX-License-Identifier: Apache-2.0

use pepper_kafka::{
    KafkaCluster,
    security::{
        AclEffect, AclOperation, AclRule, KafkaSecurity, PrincipalQuotaConfig, ResourcePattern,
        ResourceType, ScramCredential,
    },
    server::{KafkaServer, KafkaServerConfig, KafkaTlsConfig},
};
use pepper_kafka_protocol::ProtocolLimits;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let root = arguments
        .first()
        .map(PathBuf::from)
        .ok_or("usage: pepper-kafka-smoke-server DATA_DIRECTORY [CA_PEM_OUTPUT]")?;
    let secure = if let Some(ca_output) = arguments.get(1) {
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "host.docker.internal".into(),
        ])?;
        fs::write(ca_output, cert.pem())?;
        let tls = KafkaTlsConfig::from_der(
            vec![cert.der().as_ref().to_vec()],
            signing_key.serialize_der(),
        )?;
        let security = Arc::new(KafkaSecurity::open(
            root.join("security.json"),
            PrincipalQuotaConfig::default(),
            10_000,
        )?);
        security.upsert_credential(
            "qualification",
            ScramCredential::from_password(b"qualification-password", 4_096)?,
        )?;
        security.replace_acls(
            [
                ResourceType::Cluster,
                ResourceType::Topic,
                ResourceType::Group,
                ResourceType::TransactionalId,
            ]
            .into_iter()
            .map(|resource_type| AclRule {
                principal: "qualification".into(),
                resource_type,
                resource: "*".into(),
                pattern: ResourcePattern::Literal,
                operation: AclOperation::All,
                effect: AclEffect::Allow,
            })
            .collect(),
        )?;
        Some((tls, security))
    } else {
        None
    };
    let addresses = [19092, 29092, 39092]
        .map(|port| format!("127.0.0.1:{port}").parse::<SocketAddr>())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let brokers = addresses
        .iter()
        .enumerate()
        .map(|(broker, address)| (broker as i32, address.ip().to_string(), address.port()))
        .collect();
    let cluster = KafkaCluster::open(
        root,
        "pepper-client-qualification",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await?;
    for (broker_id, address) in addresses.into_iter().enumerate() {
        let listener = TcpListener::bind(address).await?;
        let server_config = if let Some((tls, security)) = &secure {
            KafkaServerConfig {
                tls: Some(tls.clone()),
                security: Some(Arc::clone(security)),
                ..KafkaServerConfig::default()
            }
        } else {
            KafkaServerConfig::default()
        };
        let server = Arc::new(KafkaServer::new(
            broker_id as i32,
            Arc::clone(&cluster),
            server_config,
        )?);
        tokio::spawn(async move {
            if let Err(error) = server.serve(listener).await {
                eprintln!("broker {broker_id} stopped: {error}");
            }
        });
    }
    println!(
        "Pepper Kafka smoke server is ready on 127.0.0.1:19092 ({})",
        if secure.is_some() {
            "TLS/SCRAM"
        } else {
            "plaintext"
        }
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}
