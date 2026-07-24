// SPDX-License-Identifier: Apache-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use kafka_protocol::{
    messages::{
        ApiKey, MetadataRequest, MetadataResponse, RequestHeader, ResponseHeader,
        SaslAuthenticateRequest, SaslAuthenticateResponse, SaslHandshakeRequest,
        SaslHandshakeResponse,
    },
    protocol::{Decodable, Encodable, HeaderVersion, StrBytes},
};
use pepper_kafka::{
    KafkaCluster,
    security::{
        AclEffect, AclOperation, AclRule, KafkaSecurity, PrincipalQuotaConfig, ResourcePattern,
        ResourceType, ScramCredential,
    },
    server::{KafkaServer, KafkaServerConfig, KafkaTlsConfig, ServerError},
};
use pepper_kafka_protocol::ProtocolLimits;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, generate_simple_self_signed,
};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

type HmacSha256 = Hmac<Sha256>;

struct SecureBroker {
    _directory: TempDir,
    address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    task: JoinHandle<()>,
    security: Arc<KafkaSecurity>,
}

impl Drop for SecureBroker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_secure_broker() -> SecureBroker {
    let directory = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.der().clone();
    let tls = KafkaTlsConfig::from_der(
        vec![certificate.as_ref().to_vec()],
        signing_key.serialize_der(),
    )
    .unwrap();
    let security = Arc::new(KafkaSecurity::new(PrincipalQuotaConfig::default(), 128).unwrap());
    security
        .upsert_credential(
            "alice",
            ScramCredential::with_salt(b"correct horse", b"qualification-salt".to_vec(), 4_096),
        )
        .unwrap();
    security
        .replace_acls(vec![
            AclRule {
                principal: "alice".into(),
                resource_type: ResourceType::Cluster,
                resource: "kafka-cluster".into(),
                pattern: ResourcePattern::Literal,
                operation: AclOperation::Describe,
                effect: AclEffect::Allow,
            },
            AclRule {
                principal: "alice".into(),
                resource_type: ResourceType::Topic,
                resource: "tenant-alice-".into(),
                pattern: ResourcePattern::Prefix,
                operation: AclOperation::All,
                effect: AclEffect::Allow,
            },
        ])
        .unwrap();
    let cluster = KafkaCluster::open(
        directory.path(),
        "secure-integration",
        0,
        vec![(0, "localhost".into(), address.port())],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    let server = Arc::new(
        KafkaServer::new(
            0,
            cluster,
            KafkaServerConfig {
                request_timeout: Duration::from_secs(2),
                write_timeout: Duration::from_secs(2),
                tls: Some(tls),
                security: Some(Arc::clone(&security)),
                ..KafkaServerConfig::default()
            },
        )
        .unwrap(),
    );
    let task = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });
    SecureBroker {
        _directory: directory,
        address,
        certificate,
        task,
        security,
    }
}

fn connector(certificate: rustls::pki_types::CertificateDer<'static>) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn connect(
    address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> TlsStream<TcpStream> {
    connector(certificate)
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap()
}

async fn exchange<S, T, R>(
    stream: &mut S,
    api_key: ApiKey,
    version: i16,
    correlation: i32,
    request: T,
) -> R
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Encodable + HeaderVersion,
    R: Decodable + HeaderVersion,
{
    let mut payload = BytesMut::new();
    RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(version)
        .with_correlation_id(correlation)
        .with_client_id(Some(StrBytes::from_static_str("secure-test")))
        .encode(&mut payload, T::header_version(version))
        .unwrap();
    request.encode(&mut payload, version).unwrap();
    stream.write_i32(payload.len() as i32).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    let size = stream.read_i32().await.unwrap();
    let mut response = BytesMut::zeroed(size as usize);
    stream.read_exact(&mut response).await.unwrap();
    let header = ResponseHeader::decode(&mut response, R::header_version(version)).unwrap();
    assert_eq!(header.correlation_id, correlation);
    let decoded = R::decode(&mut response, version).unwrap();
    assert!(!response.has_remaining());
    decoded
}

fn hmac(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn scram_hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut initial = Vec::from(salt);
    initial.extend_from_slice(&1u32.to_be_bytes());
    let mut previous = hmac(password, &initial);
    let mut result = previous;
    for _ in 1..iterations {
        previous = hmac(password, &previous);
        for index in 0..32 {
            result[index] ^= previous[index];
        }
    }
    result
}

fn scram_final(password: &[u8], client_first: &str, server_first: &str) -> String {
    let fields = server_first
        .split(',')
        .map(|field| field.split_once('=').unwrap())
        .collect::<std::collections::BTreeMap<_, _>>();
    let salt = STANDARD.decode(fields["s"]).unwrap();
    let iterations = fields["i"].parse().unwrap();
    let without_proof = format!("c=biws,r={}", fields["r"]);
    let auth = format!("{client_first},{server_first},{without_proof}");
    let salted = scram_hi(password, &salt, iterations);
    let client_key = hmac(&salted, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    let signature = hmac(&stored_key, auth.as_bytes());
    let proof = client_key
        .iter()
        .zip(signature)
        .map(|(key, signature)| key ^ signature)
        .collect::<Vec<_>>();
    format!("{without_proof},p={}", STANDARD.encode(proof))
}

async fn authenticate(
    stream: &mut TlsStream<TcpStream>,
    password: &[u8],
) -> SaslAuthenticateResponse {
    let handshake: SaslHandshakeResponse = exchange(
        stream,
        ApiKey::SaslHandshake,
        1,
        1,
        SaslHandshakeRequest::default().with_mechanism(StrBytes::from_static_str("SCRAM-SHA-256")),
    )
    .await;
    assert_eq!(handshake.error_code, 0);
    let client_first = "n=alice,r=0123456789abcdef";
    let first: SaslAuthenticateResponse = exchange(
        stream,
        ApiKey::SaslAuthenticate,
        0,
        2,
        SaslAuthenticateRequest::default()
            .with_auth_bytes(Bytes::from(format!("n,,{client_first}"))),
    )
    .await;
    assert_eq!(first.error_code, 0);
    let server_first = std::str::from_utf8(&first.auth_bytes).unwrap();
    let final_message = scram_final(password, client_first, server_first);
    exchange(
        stream,
        ApiKey::SaslAuthenticate,
        0,
        3,
        SaslAuthenticateRequest::default().with_auth_bytes(Bytes::from(final_message)),
    )
    .await
}

#[tokio::test]
async fn tls13_scram_acl_and_audit_secure_the_listener() {
    let broker = start_secure_broker().await;

    let mut plaintext = TcpStream::connect(broker.address).await.unwrap();
    plaintext.write_all(&[0, 0, 0, 0]).await.unwrap();
    let mut byte = [0u8; 1];
    let plaintext_result =
        tokio::time::timeout(Duration::from_secs(2), plaintext.read(&mut byte)).await;
    assert!(match plaintext_result {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(1)) => byte[0] == 21, // TLS alert, never a Kafka response frame.
        _ => false,
    });

    let mut tls = connect(broker.address, broker.certificate.clone()).await;
    let authenticated = authenticate(&mut tls, b"correct horse").await;
    assert_eq!(authenticated.error_code, 0);
    assert!(
        std::str::from_utf8(&authenticated.auth_bytes)
            .unwrap()
            .starts_with("v=")
    );
    let metadata: MetadataResponse = exchange(
        &mut tls,
        ApiKey::Metadata,
        1,
        4,
        MetadataRequest::default().with_topics(None),
    )
    .await;
    assert_eq!(metadata.controller_id, 0);

    let mut wrong_password = connect(broker.address, broker.certificate.clone()).await;
    assert_eq!(
        authenticate(&mut wrong_password, b"wrong password")
            .await
            .error_code,
        58
    );

    let mut legacy = connect(broker.address, broker.certificate.clone()).await;
    let legacy_handshake: SaslHandshakeResponse = exchange(
        &mut legacy,
        ApiKey::SaslHandshake,
        0,
        5,
        SaslHandshakeRequest::default().with_mechanism(StrBytes::from_static_str("SCRAM-SHA-256")),
    )
    .await;
    assert_eq!(legacy_handshake.error_code, 0);
    let client_first = "n=alice,r=legacy0123456789";
    legacy
        .write_i32((client_first.len() + 3) as i32)
        .await
        .unwrap();
    legacy
        .write_all(format!("n,,{client_first}").as_bytes())
        .await
        .unwrap();
    let challenge_bytes = legacy.read_i32().await.unwrap();
    let mut challenge = vec![0; challenge_bytes as usize];
    legacy.read_exact(&mut challenge).await.unwrap();
    let challenge = std::str::from_utf8(&challenge).unwrap();
    let final_message = scram_final(b"correct horse", client_first, challenge);
    legacy.write_i32(final_message.len() as i32).await.unwrap();
    legacy.write_all(final_message.as_bytes()).await.unwrap();
    let signature_bytes = legacy.read_i32().await.unwrap();
    let mut signature = vec![0; signature_bytes as usize];
    legacy.read_exact(&mut signature).await.unwrap();
    assert!(std::str::from_utf8(&signature).unwrap().starts_with("v="));
    let metadata: MetadataResponse = exchange(
        &mut legacy,
        ApiKey::Metadata,
        1,
        6,
        MetadataRequest::default().with_topics(None),
    )
    .await;
    assert_eq!(metadata.controller_id, 0);

    let audit = broker.security.audit_events();
    assert!(audit.iter().any(|event| {
        event.principal == "alice" && event.action == "authenticate" && event.result == "success"
    }));
    assert!(audit.iter().any(|event| {
        event.principal == "alice" && event.action == "authenticate" && event.result == "denied"
    }));
    let rendered = format!("{broker:?}", broker = broker.security);
    assert!(!rendered.contains("correct horse"));
    assert!(!rendered.contains("qualification-salt"));
}

#[tokio::test]
async fn wrong_tls_identity_and_security_without_tls_fail_closed() {
    let broker = start_secure_broker().await;
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["not-localhost.invalid".into()]).unwrap();
    let result = connector(cert.der().clone())
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            TcpStream::connect(broker.address).await.unwrap(),
        )
        .await;
    assert!(result.is_err());

    let cluster = KafkaCluster::open(
        tempfile::tempdir().unwrap().path(),
        "security-needs-tls",
        0,
        vec![(0, "localhost".into(), 9092)],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        KafkaServer::new(
            0,
            cluster,
            KafkaServerConfig {
                security: Some(Arc::new(
                    KafkaSecurity::new(PrincipalQuotaConfig::default(), 8).unwrap()
                )),
                ..KafkaServerConfig::default()
            }
        ),
        Err(ServerError::SecurityRequiresTls)
    ));
}

#[tokio::test]
async fn mtls_requires_a_trusted_client_and_maps_its_leaf_identity() {
    let directory = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let mut ca_parameters = CertificateParams::new(Vec::new()).unwrap();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_parameters, ca_key);
    let client_key = KeyPair::generate().unwrap();
    let mut client_parameters =
        CertificateParams::new(vec!["qualification-client".into()]).unwrap();
    client_parameters
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_certificate = client_parameters.signed_by(&client_key, &issuer).unwrap();

    let CertifiedKey {
        cert: server_certificate,
        signing_key: server_key,
    } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca_certificate.der().clone()).unwrap();
    let tls = KafkaTlsConfig::from_der_with_client_roots(
        vec![server_certificate.der().as_ref().to_vec()],
        server_key.serialize_der(),
        client_roots,
    )
    .unwrap();
    let principal = format!(
        "mtls:{}",
        hex::encode(blake3::hash(client_certificate.der().as_ref()).as_bytes())
    );
    let security = Arc::new(KafkaSecurity::new(PrincipalQuotaConfig::default(), 32).unwrap());
    security
        .replace_acls(vec![AclRule {
            principal,
            resource_type: ResourceType::Cluster,
            resource: "kafka-cluster".into(),
            pattern: ResourcePattern::Literal,
            operation: AclOperation::Describe,
            effect: AclEffect::Allow,
        }])
        .unwrap();
    let cluster = KafkaCluster::open(
        directory.path(),
        "mtls",
        0,
        vec![(0, "localhost".into(), address.port())],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    let server = Arc::new(
        KafkaServer::new(
            0,
            cluster,
            KafkaServerConfig {
                tls: Some(tls),
                security: Some(security),
                ..KafkaServerConfig::default()
            },
        )
        .unwrap(),
    );
    let task = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    let mut server_roots = rustls::RootCertStore::empty();
    server_roots.add(server_certificate.der().clone()).unwrap();
    let client_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(server_roots.clone())
            .with_client_auth_cert(
                vec![client_certificate.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(client_key.serialize_der()).unwrap(),
            )
            .unwrap();
    let mut stream = TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    let metadata: MetadataResponse = exchange(
        &mut stream,
        ApiKey::Metadata,
        1,
        20,
        MetadataRequest::default().with_topics(None),
    )
    .await;
    assert_eq!(metadata.controller_id, 0);

    let no_client_certificate =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(server_roots)
            .with_no_client_auth();
    let rejected = TlsConnector::from(Arc::new(no_client_certificate))
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await;
    if let Ok(mut rejected) = rejected {
        let _ = rejected.write_all(&[0, 0, 0, 0]).await;
        let mut byte = [0u8; 1];
        let outcome = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut byte)).await;
        assert!(matches!(outcome, Ok(Ok(0)) | Ok(Err(_))));
    }
    task.abort();
}

#[tokio::test]
async fn future_format_is_rejected_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("kafka-format.json"),
        br#"{"format_version":14,"minimum_reader_version":14}"#,
    )
    .unwrap();
    let opened = KafkaCluster::open(
        directory.path(),
        "future",
        0,
        vec![(0, "localhost".into(), 9092)],
        ProtocolLimits::default(),
    )
    .await;
    assert!(matches!(
        opened,
        Err(pepper_kafka::KafkaError::UnsupportedFormat {
            found: 14,
            supported: 13
        })
    ));
    assert!(!directory.path().join("controller.json").exists());
}

#[tokio::test]
async fn markerless_phase8_floor_upgrades_and_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let brokers = vec![(0, "localhost".into(), 9092)];
    let cluster = KafkaCluster::open(
        directory.path(),
        "markerless",
        0,
        brokers.clone(),
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    drop(cluster);
    let marker = std::fs::read_to_string(directory.path().join("kafka-format.json")).unwrap();
    assert!(marker.contains("\"format_version\": 13"));
    assert!(marker.contains("\"minimum_reader_version\": 8"));
    KafkaCluster::open(
        directory.path(),
        "markerless",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
}
