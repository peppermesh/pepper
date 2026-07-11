// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to read identity key {path}: {source}")]
    ReadKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write identity key {path}: {source}")]
    WriteKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse identity key {path}: {source}")]
    ParseKey {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid identity key {path}: {message}")]
    InvalidKey { path: String, message: String },
    #[error("identity key {path} does not exist and generation is disabled")]
    MissingKey { path: String },
    #[error("failed to generate random identity key material: {0}")]
    Random(String),
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    version: u8,
    algorithm: String,
    private_key_hex: String,
    public_key_hex: String,
}

impl NodeIdentity {
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        generate_if_missing: bool,
    ) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else if generate_if_missing {
            Self::generate_and_store(path)
        } else {
            Err(CryptoError::MissingKey {
                path: path.display().to_string(),
            })
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .map_err(|source| CryptoError::ReadKey {
                    path: path.display().to_string(),
                    source,
                })?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(CryptoError::InvalidKey {
                    path: path.display().to_string(),
                    message: format!(
                        "identity key permissions must be 0600 or stricter, found {mode:04o}"
                    ),
                });
            }
        }
        let bytes = fs::read(path).map_err(|source| CryptoError::ReadKey {
            path: path.display().to_string(),
            source,
        })?;
        let file: IdentityFile =
            serde_json::from_slice(&bytes).map_err(|source| CryptoError::ParseKey {
                path: path.display().to_string(),
                source,
            })?;
        Self::from_file(path, file)
    }

    pub fn generate_and_store(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| CryptoError::Random(e.to_string()))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let identity = Self::from_signing_key(signing_key);
        let file = IdentityFile {
            version: 1,
            algorithm: "ed25519".to_string(),
            private_key_hex: hex::encode(secret),
            public_key_hex: hex::encode(verifying_key.to_bytes()),
        };
        let serialized =
            serde_json::to_vec_pretty(&file).map_err(|source| CryptoError::ParseKey {
                path: path.display().to_string(),
                source,
            })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CryptoError::WriteKey {
                path: path.display().to_string(),
                source,
            })?;
        }
        write_key_file(path, &serialized)?;
        Ok(identity)
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    fn from_file(path: &Path, file: IdentityFile) -> Result<Self, CryptoError> {
        if file.version != 1 {
            return Err(CryptoError::InvalidKey {
                path: path.display().to_string(),
                message: format!("unsupported identity key version {}", file.version),
            });
        }
        if file.algorithm != "ed25519" {
            return Err(CryptoError::InvalidKey {
                path: path.display().to_string(),
                message: format!("unsupported identity algorithm {}", file.algorithm),
            });
        }
        let secret = hex::decode(&file.private_key_hex).map_err(|e| CryptoError::InvalidKey {
            path: path.display().to_string(),
            message: format!("invalid private key hex: {e}"),
        })?;
        let secret: [u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey {
            path: path.display().to_string(),
            message: "private key must be 32 bytes".to_string(),
        })?;
        let signing_key = SigningKey::from_bytes(&secret);
        let expected_public = signing_key.verifying_key().to_bytes();
        let actual_public =
            hex::decode(&file.public_key_hex).map_err(|e| CryptoError::InvalidKey {
                path: path.display().to_string(),
                message: format!("invalid public key hex: {e}"),
            })?;
        if actual_public.as_slice() != expected_public {
            return Err(CryptoError::InvalidKey {
                path: path.display().to_string(),
                message: "public key does not match private key".to_string(),
            });
        }
        Ok(Self::from_signing_key(signing_key))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let node_id = derive_node_id(&verifying_key.to_bytes());
        Self {
            signing_key,
            verifying_key,
            node_id,
        }
    }
}

pub fn derive_node_id(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    hex::encode(digest.as_bytes())
}

pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(unix)]
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::{fs::OpenOptions, io::Write};

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| CryptoError::WriteKey {
            path: path.display().to_string(),
            source,
        })?;
    file.write_all(bytes)
        .map_err(|source| CryptoError::WriteKey {
            path: path.display().to_string(),
            source,
        })?;
    file.sync_all().map_err(|source| CryptoError::WriteKey {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    fs::write(path, bytes).map_err(|source| CryptoError::WriteKey {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let first = NodeIdentity::generate_and_store(&path).unwrap();
        let second = NodeIdentity::load(&path).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.public_key_bytes(), second.public_key_bytes());
    }
}
