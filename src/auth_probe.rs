//! Complete Pair-Verify with a supplied identity, then close without content requests.

use anyhow::{ensure, Result};
use serde::Serialize;
use std::path::Path;

use crate::companion::PairingIdentity;

#[derive(Debug, Serialize)]
pub struct AuthProbeReport {
    pub authenticated: bool,
    pub content_requests_sent: bool,
}

pub async fn run(host: &str, port: u16, identity_path: &Path) -> Result<AuthProbeReport> {
    ensure!(port != 0, "auth-probe requires an explicit nonzero port");
    let identity = PairingIdentity::load(identity_path)?;
    run_with_identity(host, port, identity).await
}

async fn run_with_identity(
    host: &str,
    port: u16,
    identity: PairingIdentity,
) -> Result<AuthProbeReport> {
    let session = crate::companion_client::connect(host, port, identity).await?;
    // Dropping the established Session closes the transport; no P1/P2 or clipboard request.
    drop(session);
    Ok(AuthProbeReport {
        authenticated: true,
        content_requests_sent: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::{PairVerifyServer, PairingIdentity};
    use crate::companion_client::{read_packet, write_packet};
    use ed25519_dalek::SigningKey;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn authenticates_loopback_peer_then_closes() {
        let (client_identity, server_identity) =
            crate::companion_client::matched_loopback_identities();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut verifier = PairVerifyServer::new(server_identity);
            let m1 = read_packet(&mut stream).await.unwrap();
            let m2 = verifier.process_m1(&m1).unwrap();
            write_packet(&mut stream, &m2).await.unwrap();
            let m3 = read_packet(&mut stream).await.unwrap();
            let (m4, _) = verifier.process_m3(&m3).unwrap();
            write_packet(&mut stream, &m4).await.unwrap();
            // No content packet may follow M4.
            use tokio::io::AsyncReadExt;
            let mut byte = [0u8; 1];
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap()
        });

        let report = run_with_identity(&addr.ip().to_string(), addr.port(), client_identity)
            .await
            .unwrap();
        assert!(report.authenticated);
        assert!(!report.content_requests_sent);
        assert_eq!(server.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn rejects_unknown_loopback_peer_before_m3() {
        let client_identity = PairingIdentity {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
            device_irk: [0u8; 16],
            peers: vec![],
        };
        let server_identity = PairingIdentity {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
            device_irk: [0u8; 16],
            peers: vec![],
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut verifier = PairVerifyServer::new(server_identity);
            let m1 = read_packet(&mut stream).await.unwrap();
            let m2 = verifier.process_m1(&m1).unwrap();
            write_packet(&mut stream, &m2).await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut byte = [0u8; 1];
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap()
        });

        let result = run_with_identity(&addr.ip().to_string(), addr.port(), client_identity).await;
        assert!(result.is_err());
        assert_eq!(server.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn server_rejects_unenrolled_loopback_client_at_m3() {
        let server_signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let client_identity = PairingIdentity {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
            device_irk: [0u8; 16],
            peers: vec![("loopback-server".into(), server_signing.verifying_key())],
        };
        // This simulates an iPhone that has not enrolled the Linux identity.
        let server_identity = PairingIdentity {
            signing: server_signing,
            device_irk: [0u8; 16],
            peers: vec![],
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut verifier = PairVerifyServer::new(server_identity);
            let m1 = read_packet(&mut stream).await.unwrap();
            let m2 = verifier.process_m1(&m1).unwrap();
            write_packet(&mut stream, &m2).await.unwrap();
            let m3 = read_packet(&mut stream).await.unwrap();
            verifier.process_m3(&m3).is_err()
        });

        let result = run_with_identity(&addr.ip().to_string(), addr.port(), client_identity).await;
        assert!(result.is_err());
        assert!(server.await.unwrap(), "server must reject the untrusted M3");
    }
}
