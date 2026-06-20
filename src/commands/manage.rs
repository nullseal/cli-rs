use std::path::Path;

use anyhow::{bail, Result};

use crate::api::{ApiClient, FileMetadata, ReplaceShareRequest};
use crate::crypto::{encrypt_bytes, generate_challenge};

use super::SUPPORTED_EXTENSIONS;

const MIN_PASSWORD_LEN: usize = 3;
const SERVER_MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TEXT_LENGTH: usize = 100_000;

fn server_url(server: Option<&str>) -> Result<String> {
    server
        .map(str::to_owned)
        .or_else(|| std::env::var("CLI_APPS_CORE_URL").ok())
        .or_else(|| option_env!("CLI_APPS_CORE_URL").map(str::to_owned))
        .ok_or_else(|| anyhow::anyhow!("CLI_APPS_CORE_URL environment variable is not set"))
}

fn file_extension(filename: &str) -> String {
    Path::new(filename)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

fn parse_owner_code(owner_code: &str) -> Result<(&str, &str)> {
    let at_pos = owner_code
        .find('@')
        .ok_or_else(|| anyhow::anyhow!("Invalid owner code format. Expected: <shareId>@<secret>"))?;
    let share_id = &owner_code[..at_pos];
    if share_id.is_empty() {
        bail!("Invalid owner code: empty share ID");
    }
    Ok((share_id, owner_code))
}

pub async fn run(
    owner_code: impl Into<String>,
    action: impl Into<String>,
    content: Option<String>,
    password: Option<String>,
    content_type_flag: impl Into<String>,
    server: Option<String>,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let owner_code = owner_code.into();
    let action = action.into();
    let content_type_flag = content_type_flag.into();

    let (share_id, full_owner_code) = parse_owner_code(&owner_code)?;

    let client = ApiClient::new(server_url(server.as_deref())?);

    match action.as_str() {
        "replace" => {
            let content = content.ok_or_else(|| anyhow::anyhow!("--replace requires content"))?;
            let password = password.ok_or_else(|| anyhow::anyhow!("--replace requires a password (-p)"))?;

            if password.len() < MIN_PASSWORD_LEN {
                bail!("Password must be at least {MIN_PASSWORD_LEN} characters.");
            }

            // Verify ownership first
            output("Verifying ownership…");
            let info = client.verify_owner(share_id, full_owner_code).await?;

            // Resolve content type
            let new_content_type = resolve_content_type(&content_type_flag);

            // Validate type matches original
            if new_content_type != info.content_type {
                bail!(
                    "Content type mismatch: share is '{}' but replacement is '{}'. Cannot change type.",
                    info.content_type,
                    new_content_type
                );
            }

            // Validate and read content
            let (bytes, file_metadata) = read_content(&content, new_content_type)?;

            // Encrypt
            let content_checksum = crate::crypto::sha256_bytes(&bytes);
            let result = encrypt_bytes(&bytes, &password);
            let challenge = generate_challenge(&password);

            // Replace
            output("Replacing share content…");
            client
                .replace_share(
                    share_id,
                    ReplaceShareRequest {
                        owner_code: full_owner_code.to_owned(),
                        content_type: new_content_type.into(),
                        encrypted_payload: result.encrypted_payload,
                        encryption_metadata: result.encryption_metadata,
                        file_metadata,
                        challenge_plaintext: challenge.challenge_plaintext,
                        encrypted_challenge: challenge.encrypted_challenge,
                        challenge_metadata: challenge.challenge_metadata,
                        content_checksum,
                    },
                )
                .await?;

            eprintln!("\x1b[1;32m✓\x1b[0m Share content replaced successfully.");
        }
        "destroy" => {
            output("Verifying ownership…");
            client.verify_owner(share_id, full_owner_code).await?;

            output("Destroying share…");
            client.destroy_share(share_id, full_owner_code).await?;

            eprintln!("\x1b[1;32m✓\x1b[0m Share destroyed.");
        }
        _ => {
            bail!("Unknown action: '{action}'. Use --replace or --destroy.");
        }
    }

    Ok(())
}

fn resolve_content_type(flag: &str) -> &'static str {
    match flag {
        "pwd" => "password",
        "file" => "file",
        _ => "text",
    }
}

fn read_content(content: &str, content_type: &str) -> Result<(Vec<u8>, Option<FileMetadata>)> {
    if content_type == "file" {
        let p = Path::new(content);
        if !p.exists() {
            bail!("File not found: {content}");
        }
        let bytes = std::fs::read(p)?;
        let filename = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let extension = file_extension(&filename);
        if !SUPPORTED_EXTENSIONS.contains(&extension.as_str()) {
            bail!(
                "Unsupported file extension: {}",
                if extension.is_empty() { "(none)" } else { &extension }
            );
        }
        if bytes.len() as u64 > SERVER_MAX_BYTES {
            bail!("File exceeds upload limit (2 MB).");
        }
        Ok((
            bytes.clone(),
            Some(FileMetadata {
                size: bytes.len() as u64,
                mime_type: "application/octet-stream".into(),
                extension,
                filename,
            }),
        ))
    } else {
        if content.trim().is_empty() {
            bail!("Content cannot be empty.");
        }
        if content.len() > MAX_TEXT_LENGTH {
            bail!("Text must be {MAX_TEXT_LENGTH} characters or fewer.");
        }
        Ok((content.as_bytes().to_vec(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup() -> (MockServer, String) {
        let server = MockServer::start().await;
        let uri = server.uri();
        (server, uri)
    }

    fn mock_verify_response() -> serde_json::Value {
        serde_json::json!({
            "shareId": "testshare123",
            "contentType": "text",
            "oneTimeRead": false,
            "expiresAt": "2026-07-01T00:00:00.000Z",
            "createdAt": "2026-06-20T00:00:00.000Z"
        })
    }

    #[tokio::test]
    async fn replace_text_share() {
        let (server, uri) = setup().await;

        Mock::given(method("POST"))
            .and(path("/shares/manage/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_verify_response()))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/shares/testshare123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_verify_response()))
            .mount(&server)
            .await;

        let result = run(
            "testshare123@ownersecret",
            "replace",
            Some("new secret content".into()),
            Some("hunter2".into()),
            "txt",
            Some(uri),
            &mut |_| {},
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn destroy_share() {
        let (server, uri) = setup().await;

        Mock::given(method("POST"))
            .and(path("/shares/manage/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_verify_response()))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/shares/testshare123"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let result = run(
            "testshare123@ownersecret",
            "destroy",
            None,
            None,
            "txt",
            Some(uri),
            &mut |_| {},
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn wrong_owner_code_errors() {
        let (server, uri) = setup().await;

        Mock::given(method("POST"))
            .and(path("/shares/manage/verify"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "Invalid owner code."
            })))
            .mount(&server)
            .await;

        let result = run(
            "testshare123@wrongcode",
            "destroy",
            None,
            None,
            "txt",
            Some(uri),
            &mut |_| {},
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn replace_type_mismatch_errors() {
        let (server, uri) = setup().await;

        // Server says it's a file share
        Mock::given(method("POST"))
            .and(path("/shares/manage/verify"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "shareId": "testshare123",
                    "contentType": "file",
                    "oneTimeRead": false,
                    "expiresAt": "2026-07-01T00:00:00.000Z",
                    "createdAt": "2026-06-20T00:00:00.000Z"
                })),
            )
            .mount(&server)
            .await;

        // User tries to replace with text
        let result = run(
            "testshare123@ownersecret",
            "replace",
            Some("new text".into()),
            Some("hunter2".into()),
            "txt",
            Some(uri),
            &mut |_| {},
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Content type mismatch"));
    }

    #[tokio::test]
    async fn invalid_owner_code_format() {
        let result = run(
            "no-at-sign",
            "destroy",
            None,
            None,
            "txt",
            Some("http://localhost:1".into()),
            &mut |_| {},
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid owner code"));
    }

    #[tokio::test]
    async fn replace_missing_password_errors() {
        let result = run(
            "testshare123@secret",
            "replace",
            Some("content".into()),
            None,
            "txt",
            Some("http://localhost:1".into()),
            &mut |_| {},
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password"));
    }
}
