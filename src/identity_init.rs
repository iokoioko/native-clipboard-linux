//! Create local bootstrap material for the Linux companion-link prototype.
//!
//! This only writes local JSON files. It does not publish an identity to an
//! Apple keychain, establish Apple account trust, or imply peer acceptance.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SERVICE: &str = "RPIdentity-SameAccountDevice";
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize)]
pub struct InitSummary {
    pub identifier: String,
    pub fingerprint: String,
    pub private_path: String,
    pub public_path: String,
}

#[derive(Serialize)]
struct PrivateIdentityFile<'a> {
    ed_sk: String,
    dirk: String,
    peers: Vec<PeerFile>,
    identifier: &'a str,
}

#[derive(Serialize)]
struct PeerFile {
    label: String,
    edpk: String,
}

#[derive(Serialize)]
struct PublicIdentityFile<'a> {
    edpk: String,
    dirk: String,
    identifier: &'a str,
    #[serde(rename = "type")]
    message_type: u8,
    service: &'static str,
    label: String,
}

#[derive(Debug)]
struct CreatedFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

/// Generate a fresh Ed25519 seed, dIRK, and UUID, then create private and
/// public identity JSON files. Both files are created exclusively with mode
/// 0600. Existing paths and symlinks are never opened or overwritten.
///
/// If creating/writing the public file fails, the private file is removed only
/// if it is still the same inode this call created.
pub fn generate(private_path: &Path, public_path: &Path) -> Result<InitSummary> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes();
    let public_key = signing_key.verifying_key().to_bytes();
    let mut device_irk = [0u8; 16];
    OsRng.fill_bytes(&mut device_irk);
    let identifier = Uuid::new_v4().to_string();
    let label = format!("NativeClipboardResearch-{identifier}");

    let private_json = serde_json::to_vec_pretty(&PrivateIdentityFile {
        ed_sk: hex::encode(seed),
        dirk: hex::encode(device_irk),
        peers: Vec::new(),
        identifier: &identifier,
    })
    .context("serializing private identity JSON")?;
    let public_json = serde_json::to_vec_pretty(&PublicIdentityFile {
        edpk: hex::encode(public_key),
        dirk: hex::encode(device_irk),
        identifier: &identifier,
        message_type: 2,
        service: SERVICE,
        label,
    })
    .context("serializing public identity JSON")?;

    let created_private = write_new_private_file(private_path, &private_json)?;
    if let Err(error) = write_new_private_file(public_path, &public_json) {
        remove_if_still_same_file(&created_private);
        return Err(error).context("creating public identity file; rolled back new private file");
    }

    Ok(InitSummary {
        identifier,
        fingerprint: hex::encode(Sha256::digest(public_key)),
        private_path: private_path.to_string_lossy().into_owned(),
        public_path: public_path.to_string_lossy().into_owned(),
    })
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<CreatedFile> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .with_context(|| format!("creating new identity file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting newly created file {}", path.display()))?;
    let created = CreatedFile {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        remove_if_still_same_file(&created);
        return Err(error).with_context(|| format!("writing identity file {}", path.display()));
    }
    Ok(created)
}

fn remove_if_still_same_file(created: &CreatedFile) {
    let Ok(metadata) = fs::symlink_metadata(&created.path) else {
        return;
    };
    if metadata.file_type().is_file()
        && metadata.dev() == created.device
        && metadata.ino() == created.inode
    {
        let _ = fs::remove_file(&created.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::PairingIdentity;
    use serde_json::Value;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn generates_loadable_private_and_public_files_with_private_modes() {
        let directory = tempdir().unwrap();
        let private_path = directory.path().join("identity.json");
        let public_path = directory.path().join("identity-public.json");

        let summary = generate(&private_path, &public_path).unwrap();
        assert_eq!(summary.identifier.len(), 36);
        assert_eq!(
            summary.private_path,
            private_path.to_string_lossy().into_owned()
        );
        assert_eq!(
            summary.public_path,
            public_path.to_string_lossy().into_owned()
        );
        assert_eq!(summary.fingerprint.len(), 64);

        for path in [&private_path, &public_path] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let identity = PairingIdentity::load(&private_path).unwrap();
        assert!(identity.peers.is_empty());
        let private_json: Value =
            serde_json::from_slice(&fs::read(&private_path).unwrap()).unwrap();
        let public_json: Value = serde_json::from_slice(&fs::read(&public_path).unwrap()).unwrap();
        let public_key = identity.signing.verifying_key().to_bytes();
        let device_irk = identity.device_irk;

        assert_eq!(private_json["identifier"], summary.identifier);
        assert_eq!(private_json["peers"].as_array().unwrap().len(), 0);
        assert_eq!(public_json["identifier"], summary.identifier);
        assert_eq!(public_json["type"], 2);
        assert_eq!(public_json["service"], SERVICE);
        assert_eq!(
            public_json["label"],
            format!("NativeClipboardResearch-{}", summary.identifier)
        );
        assert_eq!(public_json["edpk"], hex::encode(public_key));
        assert_eq!(public_json["dirk"], hex::encode(device_irk));
        assert_eq!(hex::encode(Sha256::digest(public_key)), summary.fingerprint);
        assert!(public_json.get("ed_sk").is_none());
        assert!(public_json.get("peers").is_none());
    }

    #[test]
    fn refuses_existing_private_path_without_overwriting_either_file() {
        let directory = tempdir().unwrap();
        let private_path = directory.path().join("identity.json");
        let public_path = directory.path().join("identity-public.json");
        fs::write(&private_path, b"private sentinel").unwrap();
        fs::write(&public_path, b"public sentinel").unwrap();

        assert!(generate(&private_path, &public_path).is_err());
        assert_eq!(fs::read(private_path).unwrap(), b"private sentinel");
        assert_eq!(fs::read(public_path).unwrap(), b"public sentinel");
    }

    #[test]
    fn rolls_back_only_its_private_file_if_public_path_already_exists() {
        let directory = tempdir().unwrap();
        let private_path = directory.path().join("identity.json");
        let public_path = directory.path().join("identity-public.json");
        fs::write(&public_path, b"existing public sentinel").unwrap();

        assert!(generate(&private_path, &public_path).is_err());
        assert!(!private_path.exists());
        assert_eq!(fs::read(public_path).unwrap(), b"existing public sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_paths_without_touching_the_target() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.json");
        let private_path = directory.path().join("identity.json");
        let public_path = directory.path().join("identity-public.json");
        fs::write(&target, b"target sentinel").unwrap();
        symlink(&target, &private_path).unwrap();

        assert!(generate(&private_path, &public_path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target sentinel");
        assert!(!public_path.exists());
    }
}
