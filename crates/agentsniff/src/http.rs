//! Bounded HTTP response readers for untrusted network content.

use serde::de::DeserializeOwned;

/// Read a response body without allowing a peer to allocate unbounded memory.
///
/// Both the declared content length and the actual streamed byte count are
/// enforced. This covers missing, incorrect, and chunked `Content-Length`
/// responses.
pub(crate) async fn read_body_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("HTTP response exceeds the {} byte limit", max_bytes);
    }

    let mut body =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(max_bytes as u64) as usize);
    while let Some(chunk) = response.chunk().await? {
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("HTTP response length overflow"))?;
        if new_len > max_bytes {
            anyhow::bail!("HTTP response exceeds the {} byte limit", max_bytes);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Retain only a bounded prefix from a response and stop reading once full.
///
/// This is for heuristic text sampling where a complete document is not
/// required. JSON and signed artifacts must use [`read_body_limited`] so an
/// oversized object is rejected rather than parsed partially.
pub(crate) async fn read_body_prefix_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut body =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(max_bytes as u64) as usize);
    while body.len() < max_bytes {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = max_bytes - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() >= remaining {
            break;
        }
    }
    Ok(body)
}

/// Read and deserialize bounded JSON from an untrusted response.
pub(crate) async fn read_json_limited<T: DeserializeOwned>(
    response: reqwest::Response,
    max_bytes: usize,
) -> anyhow::Result<T> {
    let body = read_body_limited(response, max_bytes).await?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn response_from(raw_response: &'static [u8]) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(raw_response).await.unwrap();
        });
        reqwest::get(format!("http://{address}")).await.unwrap()
    }

    #[tokio::test]
    async fn accepts_a_body_at_the_limit() {
        let response = response_from(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest").await;
        assert_eq!(read_body_limited(response, 4).await.unwrap(), b"test");
    }

    #[tokio::test]
    async fn rejects_a_declared_oversized_body() {
        let response = response_from(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345").await;
        assert!(read_body_limited(response, 4).await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_chunked_oversized_body() {
        let response = response_from(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
        )
        .await;
        assert!(read_body_limited(response, 5).await.is_err());
    }

    #[tokio::test]
    async fn retains_only_a_bounded_text_prefix() {
        let response = response_from(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef").await;
        assert_eq!(read_body_prefix_limited(response, 3).await.unwrap(), b"abc");
    }
}
