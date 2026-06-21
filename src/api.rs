use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{ChallengeMetadata, EncryptionMetadata};

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Share not found or already destroyed")]
    ShareUnavailable,
    #[error("Wrong password")]
    WrongPassword,
    #[error("Verify session expired, please retry")]
    VerifyExpired,
    #[error("Request failed")]
    RequestFailed,
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

#[derive(Debug, Error)]
pub enum P2PVerifyError {
    #[error("Wrong password. {attempts_left} attempt(s) left.")]
    WrongPassword { attempts_left: u32 },
    #[error("Too many failed attempts. Try again in 1 hour.")]
    IpBlocked,
    #[error(transparent)]
    Api(#[from] ApiError),
}

// ── Request / response shapes ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub extension: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareRequest {
    pub content_type: String,
    pub encrypted_payload: String,
    pub encryption_metadata: EncryptionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_metadata: Option<FileMetadata>,
    pub one_time_read: bool,
    pub expires_at: String,
    pub challenge_plaintext: String,
    pub encrypted_challenge: String,
    pub challenge_metadata: ChallengeMetadata,
    pub content_checksum: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CreateShareResponse {
    pub share_id: String,
    pub share_url: String,
    pub owner_code: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharePayloadResponse {
    pub content_type: String,
    pub encrypted_payload: String,
    pub encryption_metadata: EncryptionMetadata,
    pub file_metadata: Option<ShareFileMetadata>,
    pub content_checksum: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ShareFileMetadata {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub extension: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct ShareMetadataResponse {
    pub share_id: String,
    pub content_type: String,
    pub one_time_read: bool,
    pub encrypted_challenge: String,
    pub challenge_metadata: ChallengeMetadata,
    pub verify_id: String,
    pub content_checksum: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct VerifyOwnerResponse {
    pub share_id: String,
    pub content_type: String,
    pub one_time_read: bool,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplaceShareRequest {
    pub owner_code: String,
    pub content_type: String,
    pub encrypted_payload: String,
    pub encryption_metadata: EncryptionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_metadata: Option<FileMetadata>,
    pub challenge_plaintext: String,
    pub encrypted_challenge: String,
    pub challenge_metadata: ChallengeMetadata,
    pub content_checksum: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CreateP2PSessionResponse {
    pub session_id: String,
    pub share_url: String,
    pub expires_at: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct P2PSession {
    pub session_id: String,
    pub status: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct IceServer {
    pub urls: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct VerifyErrorBody {
    code: Option<String>,
    #[serde(rename = "attemptsLeft")]
    attempts_left: Option<u32>,
}

// ── Client ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    pub async fn create_share(
        &self,
        payload: CreateShareRequest,
    ) -> Result<CreateShareResponse, ApiError> {
        let resp = self
            .client
            .post(self.url("/shares"))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(ApiError::RequestFailed);
        }
        Ok(resp.json().await?)
    }

    pub async fn get_share_metadata(
        &self,
        share_id: &str,
    ) -> Result<ShareMetadataResponse, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/shares/{}/metadata",
                urlencoding::encode(share_id)
            )))
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(ApiError::ShareUnavailable),
            s if !s.is_success() => return Err(ApiError::RequestFailed),
            _ => {}
        }
        Ok(resp.json().await?)
    }

    pub async fn get_share_payload(
        &self,
        share_id: &str,
        answer: &str,
        verify_id: &str,
    ) -> Result<SharePayloadResponse, ApiError> {
        let resp = self
            .client
            .post(self.url(&format!(
                "/shares/{}/payload",
                urlencoding::encode(share_id)
            )))
            .json(&serde_json::json!({
                "answer": answer,
                "verifyId": verify_id
            }))
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(ApiError::ShareUnavailable),
            StatusCode::FORBIDDEN => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                match body["message"].as_str() {
                    Some("wrong_password") => return Err(ApiError::WrongPassword),
                    Some("verify_expired") => return Err(ApiError::VerifyExpired),
                    _ => return Err(ApiError::RequestFailed),
                }
            }
            s if !s.is_success() => return Err(ApiError::RequestFailed),
            _ => {}
        }
        Ok(resp.json().await?)
    }

    pub async fn create_p2p_session(
        &self,
        password_proof: &str,
    ) -> Result<CreateP2PSessionResponse, ApiError> {
        let resp = self
            .client
            .post(self.url("/p2p/sessions"))
            .json(&serde_json::json!({ "passwordProof": password_proof }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(ApiError::RequestFailed);
        }
        Ok(resp.json().await?)
    }

    pub async fn verify_p2p_session(
        &self,
        session_id: &str,
        proof: &str,
    ) -> Result<(), P2PVerifyError> {
        let resp = self
            .client
            .post(self.url(&format!(
                "/p2p/sessions/{}/verify",
                urlencoding::encode(session_id)
            )))
            .json(&serde_json::json!({ "proof": proof }))
            .send()
            .await
            .map_err(ApiError::Network)?;

        if resp.status().is_success() {
            return Ok(());
        }

        match resp.status() {
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS => {
                let body: VerifyErrorBody =
                    resp.json().await.unwrap_or(VerifyErrorBody { code: None, attempts_left: None });
                match body.code.as_deref() {
                    Some("wrong_password") => Err(P2PVerifyError::WrongPassword {
                        attempts_left: body.attempts_left.unwrap_or(0),
                    }),
                    _ => Err(P2PVerifyError::IpBlocked),
                }
            }
            _ => Err(P2PVerifyError::Api(ApiError::RequestFailed)),
        }
    }

    pub async fn get_p2p_session(&self, session_id: &str) -> Result<P2PSession, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/p2p/sessions/{}",
                urlencoding::encode(session_id)
            )))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(ApiError::RequestFailed);
        }
        Ok(resp.json().await?)
    }

    pub async fn get_ice_servers(&self) -> Result<Vec<IceServer>, ApiError> {
        let resp = self
            .client
            .get(self.url("/p2p/ice-servers"))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(ApiError::RequestFailed);
        }
        Ok(resp.json().await?)
    }

    pub async fn verify_owner(
        &self,
        share_id: &str,
        owner_code: &str,
    ) -> Result<VerifyOwnerResponse, ApiError> {
        let resp = self
            .client
            .post(self.url("/shares/manage/verify"))
            .json(&serde_json::json!({
                "shareId": share_id,
                "ownerCode": owner_code
            }))
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(ApiError::ShareUnavailable),
            StatusCode::FORBIDDEN => return Err(ApiError::RequestFailed),
            s if !s.is_success() => return Err(ApiError::RequestFailed),
            _ => {}
        }
        Ok(resp.json().await?)
    }

    pub async fn replace_share(
        &self,
        share_id: &str,
        payload: ReplaceShareRequest,
    ) -> Result<(), ApiError> {
        let resp = self
            .client
            .put(self.url(&format!(
                "/shares/{}",
                urlencoding::encode(share_id)
            )))
            .json(&payload)
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(ApiError::ShareUnavailable),
            StatusCode::FORBIDDEN => return Err(ApiError::RequestFailed),
            s if !s.is_success() => return Err(ApiError::RequestFailed),
            _ => {}
        }
        Ok(())
    }

    pub async fn destroy_share(
        &self,
        share_id: &str,
        owner_code: &str,
    ) -> Result<(), ApiError> {
        let resp = self
            .client
            .delete(self.url(&format!(
                "/shares/{}",
                urlencoding::encode(share_id)
            )))
            .json(&serde_json::json!({ "ownerCode": owner_code }))
            .send()
            .await?;

        match resp.status() {
            StatusCode::NOT_FOUND => return Err(ApiError::ShareUnavailable),
            StatusCode::FORBIDDEN => return Err(ApiError::RequestFailed),
            s if !s.is_success() => return Err(ApiError::RequestFailed),
            _ => {}
        }
        Ok(())
    }

    pub async fn report_malformed(
        &self,
        share_id: &str,
    ) -> Result<(), ApiError> {
        let resp = self
            .client
            .post(self.url(&format!(
                "/shares/{}/report-malformed",
                urlencoding::encode(share_id)
            )))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(ApiError::RequestFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> (MockServer, ApiClient) {
        let server = MockServer::start().await;
        let client = ApiClient::new(server.uri());
        (server, client)
    }

    #[tokio::test]
    async fn create_share_success() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "shareId": "abc123",
                "shareUrl": "https://nullseal.com/s/abc123",
                "ownerCode": "oc123",
                "expiresAt": "2099-01-01T00:00:00Z"
            })))
            .mount(&server)
            .await;

        let resp = client
            .create_share(CreateShareRequest {
                content_type: "text".into(),
                encrypted_payload: "payload".into(),
                encryption_metadata: EncryptionMetadata {
                    algorithm: "AES-GCM".into(),
                    kdf: "PBKDF2".into(),
                    iterations: 250_000,
                    salt: "salt=".into(),
                    iv: "iv==".into(),
                },
                file_metadata: None,
                one_time_read: true,
                expires_at: "2099-01-01T00:00:00Z".into(),
                challenge_plaintext: "a".repeat(64),
                encrypted_challenge: "enc_challenge".into(),
                challenge_metadata: ChallengeMetadata {
                    salt: "csalt".into(),
                    iv: "civ".into(),
                    iterations: 250_000,
                },
                content_checksum: "a".repeat(64),
            })
            .await
            .unwrap();

        assert_eq!(resp.share_id, "abc123");
        assert_eq!(resp.owner_code, "oc123");
    }

    #[tokio::test]
    async fn get_share_payload_404_is_share_unavailable() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/shares/notfound/payload"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client.get_share_payload("notfound", "answer", "vid").await.unwrap_err();
        assert!(matches!(err, ApiError::ShareUnavailable));
    }

    #[tokio::test]
    async fn get_share_payload_500_is_request_failed() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/shares/s1/payload"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = client.get_share_payload("s1", "answer", "vid").await.unwrap_err();
        assert!(matches!(err, ApiError::RequestFailed));
    }

    #[tokio::test]
    async fn get_share_payload_403_wrong_password() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/shares/s1/payload"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "wrong_password"
            })))
            .mount(&server)
            .await;

        let err = client.get_share_payload("s1", "bad", "vid").await.unwrap_err();
        assert!(matches!(err, ApiError::WrongPassword));
    }

    #[tokio::test]
    async fn verify_p2p_wrong_password() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/p2p/sessions/sess1/verify"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "code": "wrong_password",
                "attemptsLeft": 2
            })))
            .mount(&server)
            .await;

        let err = client.verify_p2p_session("sess1", "badhash").await.unwrap_err();
        assert!(matches!(err, P2PVerifyError::WrongPassword { attempts_left: 2 }));
    }

    #[tokio::test]
    async fn verify_p2p_ip_blocked() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/p2p/sessions/sess2/verify"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "code": "ip_blocked"
            })))
            .mount(&server)
            .await;

        let err = client.verify_p2p_session("sess2", "hash").await.unwrap_err();
        assert!(matches!(err, P2PVerifyError::IpBlocked));
    }

    #[tokio::test]
    async fn get_p2p_session_success() {
        let (server, client) = setup().await;
        Mock::given(method("GET"))
            .and(path("/p2p/sessions/sess3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessionId": "sess3",
                "status": "waiting",
                "expiresAt": "2099-01-01T00:00:00Z"
            })))
            .mount(&server)
            .await;

        let session = client.get_p2p_session("sess3").await.unwrap();
        assert_eq!(session.session_id, "sess3");
        assert_eq!(session.status, "waiting");
    }

    #[tokio::test]
    async fn create_p2p_session_success() {
        let (server, client) = setup().await;
        Mock::given(method("POST"))
            .and(path("/p2p/sessions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessionId": "sess4",
                "shareUrl": "https://nullseal.com/p2p/sess4",
                "expiresAt": "2099-01-01T00:00:00Z",
                "status": "waiting"
            })))
            .mount(&server)
            .await;

        let resp = client.create_p2p_session("proofhash").await.unwrap();
        assert_eq!(resp.session_id, "sess4");
        assert_eq!(resp.share_url, "https://nullseal.com/p2p/sess4");
    }
}
