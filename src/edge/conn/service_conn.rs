//! `ServiceConn`: the dialed `EdgeConn` bundled with the SHARED pooled `EdgeChannel` — the
//! channel-lifetime contract (`close` ≠ teardown, `into_parts` for the tunneler splice,
//! `close_write` half-close). (F6 tramo 5: movido verbatim del monolito de `edge/conn`.)

use std::sync::Arc;

use crate::edge::data::{EdgeChannel, EdgeConn};
use crate::edge::error::EdgeError;

/// A live service connection: bundles the dialed `EdgeConn` with the SHARED `EdgeChannel` it rides
/// on. Since the pool slice the channel is held as an `Arc<EdgeChannel>` — the same channel the
/// connection POOL ([`EdgeClient`](crate::edge::client::EdgeClient)'s `channel_pool`) owns, so it is SHARED with the pool and any other
/// `ServiceConn` dialed over the same edge router (multiplexed by conn-id over the one rx-loop). The
/// channel's rx-loop stays alive as long as ANY `Arc` (the pool, or a live conn) holds it; its `Drop`
/// aborts the rx-loop only at the LAST `Arc`. This re-architects slice 4b's exclusive one-channel-per-
/// `ServiceConn` ownership: dropping or `close`-ing one conn no longer tears the channel down — the
/// pool keeps it for reuse (faithful: a service-conn close ≠ a router-conn close). Delegates
/// read/write/close to the inner connection.
pub struct ServiceConn {
    conn: EdgeConn,
    channel: Arc<EdgeChannel>,
}

impl std::fmt::Debug for ServiceConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceConn")
            .field("conn_id", &self.conn.conn_id())
            .field("circuit_id", &self.conn.circuit_id())
            .finish_non_exhaustive()
    }
}

impl ServiceConn {
    /// Bundle an already-dialed connection with its (pooled, shared) channel.
    #[must_use]
    pub(crate) fn from_parts(conn: EdgeConn, channel: Arc<EdgeChannel>) -> Self {
        Self { conn, channel }
    }

    /// Split into the connection's read/write halves PLUS the shared channel handle, for the tunneler
    /// splice. The caller MUST keep the returned `Arc<EdgeChannel>` alive for as long as it uses the
    /// halves: the channel drives the rx-loop that feeds the read half. With the pool the channel is
    /// SHARED (the pool holds its own `Arc`), so the rx-loop survives this handle's drop unless the
    /// pool has also released it; holding the returned `Arc` guarantees liveness regardless. See
    /// [`crate::edge::data::EdgeConn::into_split`].
    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::edge::data::EdgeReadHalf,
        crate::edge::data::EdgeWriteHalf,
        Arc<EdgeChannel>,
    ) {
        let (reader, writer) = self.conn.into_split();
        (reader, writer, self.channel)
    }

    /// The connection id assigned by the dial.
    #[must_use]
    pub fn conn_id(&self) -> u32 {
        self.conn.conn_id()
    }

    /// The circuit id reported by the router on `StateConnected`, if any.
    #[must_use]
    pub fn circuit_id(&self) -> Option<&str> {
        self.conn.circuit_id()
    }

    /// Write a payload (encrypted transparently if the service required encryption).
    ///
    /// # Errors
    /// Propagates `EdgeConn::write` errors (channel IO / crypto).
    pub async fn write(&mut self, data: &[u8]) -> Result<(), EdgeError> {
        self.conn.write(data).await
    }

    /// Read the next payload, or `None` at end of stream.
    ///
    /// # Errors
    /// Propagates `EdgeConn::read` errors (channel IO / crypto).
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, EdgeError> {
        self.conn.read().await
    }

    /// Half-close the write side: send the FIN frame so the peer sees EOF on its read side, while
    /// this connection can keep reading the other direction. Idempotent. Used by the tunneler splice
    /// to propagate a local half-close to the ziti peer. Delegates to [`EdgeConn::close_write`].
    ///
    /// # Errors
    /// Propagates `EdgeConn::close_write` errors (channel IO).
    pub async fn close_write(&self) -> Result<(), EdgeError> {
        self.conn.close_write().await
    }

    /// Close the connection: send `StateClosed` for THIS conn-id and deregister it from the channel's
    /// mux. Does NOT tear the channel down — the connection POOL owns the shared `Arc<EdgeChannel>` and
    /// keeps it alive for reuse (faithful: a service-conn close ≠ a router-conn close; the oracle's
    /// per-conn close just sends `StateClosed`, the router conn persists in the pool). The channel's
    /// rx-loop is aborted only when the LAST `Arc` (the pool's plus any sibling conn's) drops. This is
    /// the close-semantics change from slice 4b, where `ServiceConn` exclusively owned the channel and
    /// `close()` aborted the rx-loop.
    ///
    /// # Errors
    /// Propagates the connection's close error (the `StateClosed` write).
    pub async fn close(self) -> Result<(), EdgeError> {
        let ServiceConn { mut conn, channel } = self;
        conn.close().await?;
        drop(channel); // release our Arc; the pool keeps the channel for reuse (no rx-loop abort here)
        Ok(())
    }
}
