use tokio::io::{AsyncRead, AsyncReadExt};

/// Wait for a complete bounded HTTP header before a smoke origin responds.
pub async fn read_http_headers(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<()> {
    let mut request = [0; 4096];
    let mut used = 0;
    while !request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        if used == request.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP headers exceed fixture limit",
            ));
        }
        let count = stream.read(&mut request[used..]).await?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Incomplete HTTP headers",
            ));
        }
        used += count;
    }
    Ok(())
}
