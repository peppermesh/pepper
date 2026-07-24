// SPDX-License-Identifier: Apache-2.0

//! Bounded SCRAM authentication, deny-by-default ACLs, tenant quotas, and audit.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
const MAXIMUM_CREDENTIALS: usize = 100_000;
const MAXIMUM_ACL_RULES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScramCredential {
    salt: Vec<u8>,
    iterations: u32,
    stored_key: [u8; 32],
    server_key: [u8; 32],
}

impl ScramCredential {
    pub fn from_password(password: &[u8], iterations: u32) -> Result<Self, SecurityError> {
        if password.is_empty() || !(4_096..=1_000_000).contains(&iterations) {
            return Err(SecurityError::InvalidCredential);
        }
        let mut salt = vec![0u8; 18];
        getrandom::fill(&mut salt).map_err(|_| SecurityError::Random)?;
        Ok(Self::with_salt(password, salt, iterations))
    }

    pub fn with_salt(password: &[u8], salt: Vec<u8>, iterations: u32) -> Self {
        let salted = scram_hi(password, &salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key = Sha256::digest(client_key).into();
        let server_key = hmac(&salted, b"Server Key");
        Self {
            salt,
            iterations,
            stored_key,
            server_key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceType {
    Cluster,
    Topic,
    Group,
    TransactionalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclOperation {
    All,
    Read,
    Write,
    Create,
    Delete,
    Describe,
    Alter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourcePattern {
    Literal,
    Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub principal: String,
    pub resource_type: ResourceType,
    pub resource: String,
    pub pattern: ResourcePattern,
    pub operation: AclOperation,
    pub effect: AclEffect,
}

impl AclRule {
    fn matches(
        &self,
        principal: &str,
        resource_type: ResourceType,
        resource: &str,
        operation: AclOperation,
    ) -> bool {
        (self.principal == principal || self.principal == "*")
            && self.resource_type == resource_type
            && (self.operation == operation || self.operation == AclOperation::All)
            && match self.pattern {
                ResourcePattern::Literal => self.resource == resource || self.resource == "*",
                ResourcePattern::Prefix => resource.starts_with(&self.resource),
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalQuotaConfig {
    pub maximum_principals: usize,
    pub requests_per_second: u64,
    pub ingress_bytes_per_second: u64,
    pub egress_bytes_per_second: u64,
}

impl Default for PrincipalQuotaConfig {
    fn default() -> Self {
        Self {
            maximum_principals: 10_000,
            requests_per_second: 0,
            ingress_bytes_per_second: 0,
            egress_bytes_per_second: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub timestamp_ms: u64,
    pub principal: String,
    pub action: String,
    pub resource_type: Option<ResourceType>,
    pub resource: Option<String>,
    pub result: String,
}

#[derive(Debug, Clone)]
struct PrincipalUsage {
    last_refill_ms: u64,
    request_tokens: f64,
    ingress_tokens: f64,
    egress_tokens: f64,
}

struct SecurityState {
    credentials: BTreeMap<String, ScramCredential>,
    acls: Vec<AclRule>,
    usage: BTreeMap<String, PrincipalUsage>,
    audit: VecDeque<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityMetadata {
    version: u32,
    credentials: BTreeMap<String, ScramCredential>,
    acls: Vec<AclRule>,
}

pub struct KafkaSecurity {
    state: Mutex<SecurityState>,
    quota: PrincipalQuotaConfig,
    maximum_audit_events: usize,
    metadata_path: Option<PathBuf>,
    concealment_credential: ScramCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SecuritySnapshot {
    pub credentials: usize,
    pub acl_rules: usize,
    pub tracked_principals: usize,
    pub audit_events: usize,
    pub maximum_audit_events: usize,
}

impl std::fmt::Debug for KafkaSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KafkaSecurity")
            .field("credentials", &"<redacted>")
            .field("quota", &self.quota)
            .field("maximum_audit_events", &self.maximum_audit_events)
            .finish()
    }
}

impl KafkaSecurity {
    pub fn new(
        quota: PrincipalQuotaConfig,
        maximum_audit_events: usize,
    ) -> Result<Self, SecurityError> {
        if quota.maximum_principals == 0 || maximum_audit_events == 0 {
            return Err(SecurityError::InvalidConfiguration);
        }
        Ok(Self {
            state: Mutex::new(SecurityState {
                credentials: BTreeMap::new(),
                acls: Vec::new(),
                usage: BTreeMap::new(),
                audit: VecDeque::new(),
            }),
            quota,
            maximum_audit_events,
            metadata_path: None,
            concealment_credential: concealment_credential()?,
        })
    }

    pub fn open(
        path: impl AsRef<Path>,
        quota: PrincipalQuotaConfig,
        maximum_audit_events: usize,
    ) -> Result<Self, SecurityError> {
        if quota.maximum_principals == 0 || maximum_audit_events == 0 {
            return Err(SecurityError::InvalidConfiguration);
        }
        let path = path.as_ref().to_path_buf();
        let metadata = if path.exists() {
            let metadata: SecurityMetadata = serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|error| SecurityError::Persistence(error.to_string()))?;
            if metadata.version != 1 {
                return Err(SecurityError::Persistence(format!(
                    "unsupported security metadata version {}",
                    metadata.version
                )));
            }
            metadata
        } else {
            SecurityMetadata {
                version: 1,
                credentials: BTreeMap::new(),
                acls: Vec::new(),
            }
        };
        if metadata.credentials.len() > MAXIMUM_CREDENTIALS {
            return Err(SecurityError::TooManyCredentials);
        }
        if metadata.acls.len() > MAXIMUM_ACL_RULES {
            return Err(SecurityError::TooManyAclRules);
        }
        for principal in metadata.credentials.keys() {
            validate_identity(principal)?;
        }
        for acl in &metadata.acls {
            validate_identity(&acl.principal)?;
            validate_resource(&acl.resource)?;
        }
        Ok(Self {
            state: Mutex::new(SecurityState {
                credentials: metadata.credentials,
                acls: metadata.acls,
                usage: BTreeMap::new(),
                audit: VecDeque::new(),
            }),
            quota,
            maximum_audit_events,
            metadata_path: Some(path),
            concealment_credential: concealment_credential()?,
        })
    }

    pub fn upsert_credential(
        &self,
        username: impl Into<String>,
        credential: ScramCredential,
    ) -> Result<(), SecurityError> {
        let username = username.into();
        validate_identity(&username)?;
        let mut state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        if !state.credentials.contains_key(&username)
            && state.credentials.len() >= MAXIMUM_CREDENTIALS
        {
            return Err(SecurityError::TooManyCredentials);
        }
        let previous = state.credentials.insert(username.clone(), credential);
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.credentials.insert(username.clone(), previous);
                }
                None => {
                    state.credentials.remove(&username);
                }
            }
            return Err(error);
        }
        self.audit_locked(
            &mut state,
            &username,
            "credential_change",
            None,
            None,
            "success",
        );
        Ok(())
    }

    pub fn replace_acls(&self, mut acls: Vec<AclRule>) -> Result<(), SecurityError> {
        if acls.len() > MAXIMUM_ACL_RULES {
            return Err(SecurityError::TooManyAclRules);
        }
        for acl in &acls {
            validate_identity(&acl.principal)?;
            validate_resource(&acl.resource)?;
        }
        acls.sort_by(|left, right| {
            (
                &left.principal,
                left.resource_type as u8,
                &left.resource,
                left.operation as u8,
                left.effect as u8,
            )
                .cmp(&(
                    &right.principal,
                    right.resource_type as u8,
                    &right.resource,
                    right.operation as u8,
                    right.effect as u8,
                ))
        });
        let mut state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        let previous = std::mem::replace(&mut state.acls, acls);
        if let Err(error) = self.persist_locked(&state) {
            state.acls = previous;
            return Err(error);
        }
        self.audit_locked(&mut state, "system", "acl_change", None, None, "success");
        Ok(())
    }

    pub fn handshake(
        &self,
        session: &mut SaslSession,
        mechanism: &str,
    ) -> Result<(), SecurityError> {
        if mechanism != "SCRAM-SHA-256" || !matches!(session, SaslSession::Initial) {
            self.audit("anonymous", "sasl_handshake", None, None, "denied");
            return Err(SecurityError::UnsupportedMechanism);
        }
        *session = SaslSession::Ready;
        Ok(())
    }

    pub fn authenticate(
        &self,
        session: &mut SaslSession,
        message: &[u8],
    ) -> Result<SaslStep, SecurityError> {
        if message.len() > 32 * 1024 {
            return Err(SecurityError::MalformedScram);
        }
        match session {
            SaslSession::Ready => self.client_first(session, message),
            SaslSession::Challenge { .. } => self.client_final(session, message),
            _ => Err(SecurityError::InvalidSaslState),
        }
    }

    fn client_first(
        &self,
        session: &mut SaslSession,
        message: &[u8],
    ) -> Result<SaslStep, SecurityError> {
        let message = std::str::from_utf8(message).map_err(|_| SecurityError::MalformedScram)?;
        let client_first_bare = message
            .strip_prefix("n,,")
            .ok_or(SecurityError::MalformedScram)?;
        let attributes = attributes(client_first_bare)?;
        let username =
            unescape_username(attributes.get(&'n').ok_or(SecurityError::MalformedScram)?)?;
        validate_identity(&username)?;
        let client_nonce = attributes
            .get(&'r')
            .filter(|nonce| nonce.len() >= 16)
            .ok_or(SecurityError::MalformedScram)?
            .to_string();
        let credential = self
            .state
            .lock()
            .map_err(|_| SecurityError::Lock)?
            .credentials
            .get(&username)
            .cloned();
        let credential_exists = credential.is_some();
        let credential = credential.unwrap_or_else(|| self.concealment_credential.clone());
        let mut nonce = [0u8; 18];
        getrandom::fill(&mut nonce).map_err(|_| SecurityError::Random)?;
        let combined_nonce = format!("{client_nonce}{}", STANDARD.encode(nonce));
        let server_first = format!(
            "r={combined_nonce},s={},i={}",
            STANDARD.encode(&credential.salt),
            credential.iterations
        );
        *session = SaslSession::Challenge {
            username,
            client_first_bare: client_first_bare.to_string(),
            server_first: server_first.clone(),
            combined_nonce,
            credential,
            credential_exists,
        };
        Ok(SaslStep {
            bytes: server_first.into_bytes(),
            principal: None,
            complete: false,
        })
    }

    fn client_final(
        &self,
        session: &mut SaslSession,
        message: &[u8],
    ) -> Result<SaslStep, SecurityError> {
        let SaslSession::Challenge {
            username,
            client_first_bare,
            server_first,
            combined_nonce,
            credential,
            credential_exists,
        } = session
        else {
            return Err(SecurityError::InvalidSaslState);
        };
        let final_message =
            std::str::from_utf8(message).map_err(|_| SecurityError::MalformedScram)?;
        let (without_proof, proof) = final_message
            .rsplit_once(",p=")
            .ok_or(SecurityError::MalformedScram)?;
        let final_attributes = attributes(without_proof)?;
        if final_attributes.get(&'c').map(String::as_str) != Some("biws")
            || final_attributes.get(&'r').map(String::as_str) != Some(combined_nonce.as_str())
        {
            self.audit(username, "authenticate", None, None, "denied");
            return Err(SecurityError::Authentication);
        }
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let proof = STANDARD
            .decode(proof)
            .map_err(|_| SecurityError::MalformedScram)?;
        if proof.len() != 32 {
            return Err(SecurityError::MalformedScram);
        }
        let signature = hmac(&credential.stored_key, auth_message.as_bytes());
        let mut client_key = [0u8; 32];
        for index in 0..32 {
            client_key[index] = proof[index] ^ signature[index];
        }
        let candidate: [u8; 32] = Sha256::digest(client_key).into();
        if !constant_time_eq(&candidate, &credential.stored_key) || !*credential_exists {
            self.audit(username, "authenticate", None, None, "denied");
            return Err(SecurityError::Authentication);
        }
        let server_signature = hmac(&credential.server_key, auth_message.as_bytes());
        let principal = username.clone();
        *session = SaslSession::Authenticated {
            principal: principal.clone(),
        };
        self.audit(&principal, "authenticate", None, None, "success");
        Ok(SaslStep {
            bytes: format!("v={}", STANDARD.encode(server_signature)).into_bytes(),
            principal: Some(principal),
            complete: true,
        })
    }

    pub fn authorize(
        &self,
        principal: &str,
        resource_type: ResourceType,
        resource: &str,
        operation: AclOperation,
    ) -> Result<(), SecurityError> {
        validate_resource(resource)?;
        let state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        let mut allow = false;
        for acl in &state.acls {
            if acl.matches(principal, resource_type, resource, operation) {
                if acl.effect == AclEffect::Deny {
                    drop(state);
                    self.audit(
                        principal,
                        "authorize",
                        Some(resource_type),
                        Some(resource),
                        "denied",
                    );
                    return Err(SecurityError::Authorization);
                }
                allow = true;
            }
        }
        drop(state);
        if allow {
            Ok(())
        } else {
            self.audit(
                principal,
                "authorize",
                Some(resource_type),
                Some(resource),
                "denied",
            );
            Err(SecurityError::Authorization)
        }
    }

    pub fn admit(&self, principal: &str, ingress: u64, egress: u64) -> Result<(), SecurityError> {
        let now = now_ms();
        let mut state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        if !state.usage.contains_key(principal)
            && state.usage.len() >= self.quota.maximum_principals
        {
            return Err(SecurityError::Quota);
        }
        let usage = state
            .usage
            .entry(principal.to_string())
            .or_insert_with(|| PrincipalUsage::full(now, self.quota));
        usage.refill(now, self.quota);
        let denied = !available(self.quota.requests_per_second, usage.request_tokens, 1)
            || !available(
                self.quota.ingress_bytes_per_second,
                usage.ingress_tokens,
                ingress,
            )
            || !available(
                self.quota.egress_bytes_per_second,
                usage.egress_tokens,
                egress,
            );
        if denied {
            drop(state);
            self.audit(principal, "quota", None, None, "denied");
            return Err(SecurityError::Quota);
        }
        charge(self.quota.requests_per_second, &mut usage.request_tokens, 1);
        charge(
            self.quota.ingress_bytes_per_second,
            &mut usage.ingress_tokens,
            ingress,
        );
        charge(
            self.quota.egress_bytes_per_second,
            &mut usage.egress_tokens,
            egress,
        );
        Ok(())
    }

    pub fn admit_egress(&self, principal: &str, egress: u64) -> Result<(), SecurityError> {
        let now = now_ms();
        let mut state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        if !state.usage.contains_key(principal)
            && state.usage.len() >= self.quota.maximum_principals
        {
            return Err(SecurityError::Quota);
        }
        let usage = state
            .usage
            .entry(principal.to_string())
            .or_insert_with(|| PrincipalUsage::full(now, self.quota));
        usage.refill(now, self.quota);
        if !available(
            self.quota.egress_bytes_per_second,
            usage.egress_tokens,
            egress,
        ) {
            drop(state);
            self.audit(principal, "quota", None, None, "denied");
            return Err(SecurityError::Quota);
        }
        charge(
            self.quota.egress_bytes_per_second,
            &mut usage.egress_tokens,
            egress,
        );
        Ok(())
    }

    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| state.audit.iter().cloned().collect(),
        )
    }

    pub fn snapshot(&self) -> Result<SecuritySnapshot, SecurityError> {
        let state = self.state.lock().map_err(|_| SecurityError::Lock)?;
        Ok(SecuritySnapshot {
            credentials: state.credentials.len(),
            acl_rules: state.acls.len(),
            tracked_principals: state.usage.len(),
            audit_events: state.audit.len(),
            maximum_audit_events: self.maximum_audit_events,
        })
    }

    pub fn audit_administrative_request(
        &self,
        principal: &str,
        operation: &str,
        resource_type: ResourceType,
        resource: &str,
    ) {
        self.audit(
            principal,
            operation,
            Some(resource_type),
            Some(resource),
            "admitted",
        );
    }

    fn audit(
        &self,
        principal: &str,
        action: &str,
        resource_type: Option<ResourceType>,
        resource: Option<&str>,
        result: &str,
    ) {
        if let Ok(mut state) = self.state.lock() {
            self.audit_locked(
                &mut state,
                principal,
                action,
                resource_type,
                resource,
                result,
            );
        }
    }

    fn persist_locked(&self, state: &SecurityState) -> Result<(), SecurityError> {
        let Some(path) = &self.metadata_path else {
            return Ok(());
        };
        let metadata = SecurityMetadata {
            version: 1,
            credentials: state.credentials.clone(),
            acls: state.acls.clone(),
        };
        let encoded = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| SecurityError::Persistence(error.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staging = path.with_extension("json.next");
        write_private(&staging, &encoded)?;
        std::fs::File::open(&staging)?.sync_all()?;
        std::fs::rename(&staging, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn audit_locked(
        &self,
        state: &mut SecurityState,
        principal: &str,
        action: &str,
        resource_type: Option<ResourceType>,
        resource: Option<&str>,
        result: &str,
    ) {
        while state.audit.len() >= self.maximum_audit_events {
            state.audit.pop_front();
        }
        state.audit.push_back(AuditEvent {
            timestamp_ms: now_ms(),
            principal: bounded(principal),
            action: bounded(action),
            resource_type,
            resource: resource.map(bounded),
            result: bounded(result),
        });
    }
}

#[derive(Clone, Default)]
pub enum SaslSession {
    #[default]
    Initial,
    Ready,
    Challenge {
        username: String,
        client_first_bare: String,
        server_first: String,
        combined_nonce: String,
        credential: ScramCredential,
        credential_exists: bool,
    },
    Authenticated {
        principal: String,
    },
}

impl std::fmt::Debug for SaslSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => formatter.write_str("SaslSession::Initial"),
            Self::Ready => formatter.write_str("SaslSession::Ready"),
            Self::Challenge { username, .. } => formatter
                .debug_struct("SaslSession::Challenge")
                .field("username", username)
                .field("scram_state", &"<redacted>")
                .finish(),
            Self::Authenticated { principal } => formatter
                .debug_struct("SaslSession::Authenticated")
                .field("principal", principal)
                .finish(),
        }
    }
}

impl SaslSession {
    pub fn principal(&self) -> Option<&str> {
        match self {
            Self::Authenticated { principal } => Some(principal),
            _ => None,
        }
    }
}

pub struct SaslStep {
    pub bytes: Vec<u8>,
    pub principal: Option<String>,
    pub complete: bool,
}

fn attributes(message: &str) -> Result<BTreeMap<char, String>, SecurityError> {
    let mut result = BTreeMap::new();
    for attribute in message.split(',') {
        let (name, value) = attribute
            .split_once('=')
            .ok_or(SecurityError::MalformedScram)?;
        let mut chars = name.chars();
        let name = chars.next().ok_or(SecurityError::MalformedScram)?;
        if chars.next().is_some() || value.is_empty() || result.insert(name, value.into()).is_some()
        {
            return Err(SecurityError::MalformedScram);
        }
    }
    Ok(result)
}

fn unescape_username(username: &str) -> Result<String, SecurityError> {
    let mut result = String::with_capacity(username.len());
    let mut bytes = username.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'=' {
            result.push(byte as char);
            continue;
        }
        match (bytes.next(), bytes.next()) {
            (Some(b'2'), Some(b'C')) => result.push(','),
            (Some(b'3'), Some(b'D')) => result.push('='),
            _ => return Err(SecurityError::MalformedScram),
        }
    }
    Ok(result)
}

fn scram_hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut first = Vec::with_capacity(salt.len() + 4);
    first.extend_from_slice(salt);
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut previous = hmac(password, &first);
    let mut result = previous;
    for _ in 1..iterations {
        previous = hmac(password, &previous);
        for index in 0..32 {
            result[index] ^= previous[index];
        }
    }
    result
}

fn concealment_credential() -> Result<ScramCredential, SecurityError> {
    let mut secret = [0u8; 32];
    let mut salt = vec![0u8; 18];
    getrandom::fill(&mut secret).map_err(|_| SecurityError::Random)?;
    getrandom::fill(&mut salt).map_err(|_| SecurityError::Random)?;
    Ok(ScramCredential::with_salt(&secret, salt, 4_096))
}

fn hmac(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary keys");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn validate_identity(value: &str) -> Result<(), SecurityError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(SecurityError::InvalidIdentity);
    }
    Ok(())
}

fn validate_resource(value: &str) -> Result<(), SecurityError> {
    if value.is_empty() || value.len() > 32 * 1024 || value.chars().any(char::is_control) {
        return Err(SecurityError::InvalidResource);
    }
    Ok(())
}

impl PrincipalUsage {
    fn full(now_ms: u64, quota: PrincipalQuotaConfig) -> Self {
        Self {
            last_refill_ms: now_ms,
            request_tokens: quota.requests_per_second as f64,
            ingress_tokens: quota.ingress_bytes_per_second as f64,
            egress_tokens: quota.egress_bytes_per_second as f64,
        }
    }

    fn refill(&mut self, now_ms: u64, quota: PrincipalQuotaConfig) {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms) as f64 / 1_000.0;
        self.request_tokens = refill(self.request_tokens, quota.requests_per_second, elapsed);
        self.ingress_tokens = refill(self.ingress_tokens, quota.ingress_bytes_per_second, elapsed);
        self.egress_tokens = refill(self.egress_tokens, quota.egress_bytes_per_second, elapsed);
        self.last_refill_ms = now_ms;
    }
}

fn refill(tokens: f64, limit: u64, elapsed_seconds: f64) -> f64 {
    if limit == 0 {
        0.0
    } else {
        (tokens + elapsed_seconds * limit as f64).min(limit as f64)
    }
}

fn available(limit: u64, tokens: f64, amount: u64) -> bool {
    limit == 0 || tokens >= amount as f64
}

fn charge(limit: u64, tokens: &mut f64, amount: u64) {
    if limit > 0 {
        *tokens -= amount as f64;
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(256).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("invalid security configuration")]
    InvalidConfiguration,
    #[error("invalid SCRAM credential")]
    InvalidCredential,
    #[error("invalid principal identity")]
    InvalidIdentity,
    #[error("invalid ACL resource")]
    InvalidResource,
    #[error("unsupported SASL mechanism")]
    UnsupportedMechanism,
    #[error("malformed SCRAM message")]
    MalformedScram,
    #[error("invalid SASL state")]
    InvalidSaslState,
    #[error("authentication failed")]
    Authentication,
    #[error("authorization failed")]
    Authorization,
    #[error("principal quota exceeded")]
    Quota,
    #[error("secure random generation failed")]
    Random,
    #[error("security state lock poisoned")]
    Lock,
    #[error("security credential limit exceeded")]
    TooManyCredentials,
    #[error("security ACL rule limit exceeded")]
    TooManyAclRules,
    #[error("security metadata persistence failed: {0}")]
    Persistence(String),
    #[error("security metadata I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_final(password: &[u8], client_first_bare: &str, server_first: &str) -> String {
        let server = attributes(server_first).unwrap();
        let salt = STANDARD.decode(&server[&'s']).unwrap();
        let iterations = server[&'i'].parse().unwrap();
        let final_without_proof = format!("c=biws,r={}", server[&'r']);
        let auth = format!("{client_first_bare},{server_first},{final_without_proof}");
        let salted = scram_hi(password, &salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let signature = hmac(&stored_key, auth.as_bytes());
        let proof = client_key
            .iter()
            .zip(signature)
            .map(|(key, signature)| key ^ signature)
            .collect::<Vec<_>>();
        format!("{final_without_proof},p={}", STANDARD.encode(proof))
    }

    #[test]
    fn scram_acl_deny_precedence_quota_and_audit_are_bounded() {
        let security = KafkaSecurity::new(
            PrincipalQuotaConfig {
                maximum_principals: 2,
                requests_per_second: 2,
                ingress_bytes_per_second: 100,
                egress_bytes_per_second: 100,
            },
            8,
        )
        .unwrap();
        security
            .upsert_credential(
                "alice",
                ScramCredential::with_salt(b"correct horse", b"fixed-salt".to_vec(), 4096),
            )
            .unwrap();
        security
            .replace_acls(vec![
                AclRule {
                    principal: "alice".into(),
                    resource_type: ResourceType::Topic,
                    resource: "tenant-".into(),
                    pattern: ResourcePattern::Prefix,
                    operation: AclOperation::Read,
                    effect: AclEffect::Allow,
                },
                AclRule {
                    principal: "alice".into(),
                    resource_type: ResourceType::Topic,
                    resource: "tenant-secret".into(),
                    pattern: ResourcePattern::Literal,
                    operation: AclOperation::Read,
                    effect: AclEffect::Deny,
                },
            ])
            .unwrap();
        let mut session = SaslSession::default();
        security.handshake(&mut session, "SCRAM-SHA-256").unwrap();
        let first_bare = "n=alice,r=0123456789abcdef";
        let challenge = security
            .authenticate(&mut session, format!("n,,{first_bare}").as_bytes())
            .unwrap();
        let server_first = String::from_utf8(challenge.bytes).unwrap();
        let final_message = client_final(b"correct horse", first_bare, &server_first);
        assert!(
            security
                .authenticate(&mut session, final_message.as_bytes())
                .unwrap()
                .complete
        );
        assert_eq!(session.principal(), Some("alice"));
        security
            .authorize(
                "alice",
                ResourceType::Topic,
                "tenant-public",
                AclOperation::Read,
            )
            .unwrap();
        assert!(
            security
                .authorize(
                    "alice",
                    ResourceType::Topic,
                    "tenant-secret",
                    AclOperation::Read,
                )
                .is_err()
        );
        security.admit("alice", 10, 10).unwrap();
        security.admit("alice", 10, 10).unwrap();
        assert!(security.admit("alice", 1, 1).is_err());
        assert!(security.admit("bob", 1, 1).is_ok());
        assert!(security.audit_events().len() <= 8);
        let encoded = serde_json::to_string(&security.audit_events()).unwrap();
        assert!(!encoded.contains("correct horse"));
        assert!(!encoded.contains("stored_key"));
    }

    #[test]
    fn adversarial_scram_and_acl_inputs_fail_closed() {
        let security = KafkaSecurity::new(PrincipalQuotaConfig::default(), 4).unwrap();
        security
            .upsert_credential(
                "tenant-a",
                ScramCredential::with_salt(b"password", vec![3; 18], 4_096),
            )
            .unwrap();
        security
            .replace_acls(vec![AclRule {
                principal: "tenant-a".into(),
                resource_type: ResourceType::Topic,
                resource: "tenant-a.".into(),
                pattern: ResourcePattern::Prefix,
                operation: AclOperation::Read,
                effect: AclEffect::Allow,
            }])
            .unwrap();
        assert!(
            security
                .authorize(
                    "tenant-a",
                    ResourceType::Topic,
                    "tenant-a.events",
                    AclOperation::Read
                )
                .is_ok()
        );
        for (principal, resource_type, resource, operation) in [
            (
                "tenant-a",
                ResourceType::Topic,
                "tenant-ab.events",
                AclOperation::Read,
            ),
            (
                "tenant-a",
                ResourceType::Group,
                "tenant-a.group",
                AclOperation::Read,
            ),
            (
                "tenant-b",
                ResourceType::Topic,
                "tenant-a.events",
                AclOperation::Read,
            ),
        ] {
            assert!(
                security
                    .authorize(principal, resource_type, resource, operation)
                    .is_err()
            );
        }
        let mut session = SaslSession::default();
        assert!(security.handshake(&mut session, "PLAIN").is_err());
        assert!(matches!(session, SaslSession::Initial));
        security.handshake(&mut session, "SCRAM-SHA-256").unwrap();
        for malformed in [
            Vec::from(&b"\xff\xfe"[..]),
            b"n,,n=tenant-a,r=short".to_vec(),
            vec![b'x'; 32 * 1024 + 1],
        ] {
            assert!(security.authenticate(&mut session, &malformed).is_err());
        }
        let mut unknown = SaslSession::default();
        security.handshake(&mut unknown, "SCRAM-SHA-256").unwrap();
        let first = "n=does-not-exist,r=0123456789abcdef";
        let challenge = security
            .authenticate(&mut unknown, format!("n,,{first}").as_bytes())
            .unwrap();
        let challenge = String::from_utf8(challenge.bytes).unwrap();
        let final_message = client_final(b"guessed-password", first, &challenge);
        assert!(
            security
                .authenticate(&mut unknown, final_message.as_bytes())
                .is_err()
        );
        assert!(!format!("{unknown:?}").contains("stored_key"));
        assert!(security.audit_events().len() <= 4);
    }

    #[test]
    fn credential_verifiers_and_acls_reopen_without_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("security.json");
        let security = KafkaSecurity::open(&path, PrincipalQuotaConfig::default(), 16).unwrap();
        security
            .upsert_credential(
                "alice",
                ScramCredential::with_salt(b"never-persist-me", vec![4; 18], 4_096),
            )
            .unwrap();
        security
            .replace_acls(vec![AclRule {
                principal: "alice".into(),
                resource_type: ResourceType::Topic,
                resource: "alice.".into(),
                pattern: ResourcePattern::Prefix,
                operation: AclOperation::All,
                effect: AclEffect::Allow,
            }])
            .unwrap();
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("never-persist-me"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        drop(security);
        let reopened = KafkaSecurity::open(&path, PrincipalQuotaConfig::default(), 16).unwrap();
        reopened
            .authorize(
                "alice",
                ResourceType::Topic,
                "alice.events",
                AclOperation::Write,
            )
            .unwrap();
        let mut session = SaslSession::default();
        reopened.handshake(&mut session, "SCRAM-SHA-256").unwrap();
        let first = "n=alice,r=0123456789abcdef";
        let challenge = reopened
            .authenticate(&mut session, format!("n,,{first}").as_bytes())
            .unwrap();
        let server_first = String::from_utf8(challenge.bytes).unwrap();
        let final_message = client_final(b"never-persist-me", first, &server_first);
        assert!(
            reopened
                .authenticate(&mut session, final_message.as_bytes())
                .unwrap()
                .complete
        );
    }
}
