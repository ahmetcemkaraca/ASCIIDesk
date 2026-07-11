use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tracing::{debug, error};

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Timeout")]
    Timeout,
}

pub struct MessageStream<SendMsg, RecvMsg, S> {
    ws_stream: WebSocketStream<S>,
    _phantom: std::marker::PhantomData<(SendMsg, RecvMsg)>,
}

impl<SendMsg, RecvMsg, S> MessageStream<SendMsg, RecvMsg, S>
where
    SendMsg: Serialize,
    RecvMsg: DeserializeOwned,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    pub fn new(ws_stream: WebSocketStream<S>) -> Self {
        Self {
            ws_stream,
            _phantom: std::marker::PhantomData,
        }
    }

    pub async fn send(&mut self, msg: &SendMsg) -> Result<(), TransportError> {
        let serialized = serde_json::to_string(msg)?;
        debug!("Sending message: {}", serialized);
        self.ws_stream.send(WsMessage::Text(serialized)).await?;
        Ok(())
    }

    pub async fn next(&mut self) -> Result<RecvMsg, TransportError> {
        while let Some(msg_res) = self.ws_stream.next().await {
            let msg = msg_res?;
            match msg {
                WsMessage::Text(text) => {
                    debug!("Received text message: {}", text);
                    let parsed: RecvMsg = serde_json::from_str(&text)?;
                    return Ok(parsed);
                }
                WsMessage::Binary(bin) => {
                    debug!("Received binary message of size {}", bin.len());
                    let parsed: RecvMsg = serde_json::from_slice(&bin)?;
                    return Ok(parsed);
                }
                WsMessage::Ping(payload) => {
                    // Send Pong back
                    debug!("Received Ping, sending Pong");
                    if let Err(e) = self.ws_stream.send(WsMessage::Pong(payload)).await {
                        error!("Failed to send Pong: {}", e);
                    }
                }
                WsMessage::Pong(_) => {
                    debug!("Received Pong");
                }
                WsMessage::Close(_) => {
                    return Err(TransportError::ConnectionClosed);
                }
                _ => {}
            }
        }
        Err(TransportError::ConnectionClosed)
    }

    pub async fn close(&mut self) -> Result<(), TransportError> {
        self.ws_stream.close(None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{accept_async, connect_async};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    enum TestMsg {
        Ping,
        Pong,
        Data(String),
    }

    #[tokio::test]
    async fn test_websocket_message_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = accept_async(stream).await.unwrap();
            let mut stream = MessageStream::<TestMsg, TestMsg, _>::new(ws);
            
            // Read client message
            let msg = stream.next().await.unwrap();
            assert_eq!(msg, TestMsg::Data("hello from client".to_string()));

            // Send reply
            stream.send(&TestMsg::Data("hello from server".to_string())).await.unwrap();
        });

        // Run client
        let url = format!("ws://{}", addr);
        let (ws, _) = connect_async(&url).await.unwrap();
        let mut client_stream = MessageStream::<TestMsg, TestMsg, _>::new(ws);

        client_stream.send(&TestMsg::Data("hello from client".to_string())).await.unwrap();
        let reply = client_stream.next().await.unwrap();
        assert_eq!(reply, TestMsg::Data("hello from server".to_string()));

        server_task.await.unwrap();
    }
}

