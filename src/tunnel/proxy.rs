//! Proxy-TCP tunneler mode: a local TCP listener whose accepted connections are spliced onto a
//! dialed ziti service connection, bidirectionally, with TCP-style half-close.
//!
//! Oracle: `openziti/ziti` v2.0.0 `tunnel/tunnel.go:86-147` (`Run`/`myCopy`). `Run` starts two
//! goroutines — `myCopy(client, ziti)` and `myCopy(ziti, client)` — and waits for BOTH (`for count
//! := 2`). `myCopy` copies until EOF/error, then (with `halfClose`) calls `CloseWrite()` on its
//! destination (the error is only logged, it does NOT abort the other direction). After both
//! finish, `Run`'s defer does a full `Close()` of both connections. We map that exactly:
//! `halfClose` is always true for the TCP proxy; the ziti half-close is the FIN frame
//! (`EdgeWriteHalf::close_write`, oracle `conn.go:242-256`), the socket half-close is a TCP
//! shutdown; the final ziti full-close is `EdgeWriteHalf::close` (StateClosed + deregister).

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::edge::client::EdgeClient;
use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};

/// Copy buffer for the socket→ziti direction, byte-faithful to the oracle's `myCopy`
/// (`copyBuf := make([]byte, 0x4000-17)`, tunnel.go): a ~16 KiB buffer "so UDP payloads aren't
/// chunked when sending to tunnelers with smaller MTU; 17 bytes covers encryption overhead". It
/// matters for fidelity here because `EdgeWriteHalf::write` emits ONE Data frame per call, so this
/// read cap is also the max Data-frame payload — matching the oracle's framing (well under
/// `MAX_DATA_SECTION` = 1 MiB). `pub(crate)` so the proxy-UDP path (T3) reuses the SAME oracle
/// `copyBuf` for its ziti→udp datagram split (`tunnel::udp`).
pub(crate) const PROXY_BUF: usize = 0x4000 - 17;

/// Splice a socket onto a ziti connection's read/write halves, bidirectionally, until both
/// directions reach EOF (or error), mirroring the oracle's `Run`/`myCopy`.
///
/// Both directions run CONCURRENTLY under one `tokio::join!` (not two `'static` tasks): the field
/// sets of the two halves are disjoint, so each direction borrows its own half mutably without
/// conflict, and the caller keeps the owning channel alive on the stack across the join (it drives
/// the rx-loop that feeds `zr`). This is the same shape as the oracle's two goroutines (IO-bound,
/// so parallelism is irrelevant).
///
/// Per direction, on EOF AND on a hard error (logged, not propagated to abort the peer direction),
/// the destination's write side is half-closed: socket→ziti ⇒ `zw.close_write()` (FIN frame);
/// ziti→socket ⇒ `sock_w.shutdown()`. After both directions finish, the ziti connection is
/// full-closed once (`zw.close()` = StateClosed + deregister, the oracle's `zitiConn.Close()`); the
/// socket halves drop at end of scope (TCP close, the oracle's `clientConn.Close()`).
///
/// The shared `Arc<EdgeChannel>` is NOT closed here: since the pool slice the channel is owned by the
/// connection pool and kept for reuse (the caller just drops its `Arc` clone — see [`run_tcp_proxy`]).
/// The channel must outlive this call (the caller holds its `Arc` on the stack across the join).
///
/// # Errors
/// Returns the first copy error observed (the connection is still torn down regardless); callers
/// typically just log it.
pub async fn splice<S>(mut zr: EdgeReadHalf, mut zw: EdgeWriteHalf, socket: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sock_r, mut sock_w) = tokio::io::split(socket);

    let s2z = async {
        let res = pump_sock_to_ziti(&mut sock_r, &mut zw).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "proxy: socket->ziti copy failed");
        }
        // Oracle myCopy: half-close the destination (ziti) on EOF AND on error.
        let _ = zw.close_write().await;
        res
    };
    let z2s = async {
        let res = pump_ziti_to_sock(&mut zr, &mut sock_w).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "proxy: ziti->socket copy failed");
        }
        // Oracle myCopy: half-close the destination (socket) on EOF AND on error.
        let _ = sock_w.shutdown().await;
        res
    };

    // Oracle Run: wait for BOTH directions (`for count := 2`).
    let (r_s2z, r_z2s) = tokio::join!(s2z, z2s);

    // Oracle Run defer: full close of the ziti conn (once). The socket halves drop here.
    let _ = zw.close().await;

    r_s2z.and(r_z2s)
}

/// socket→ziti: copy raw socket bytes into ziti `write` (which frames + encrypts). Returns on
/// socket EOF (`Ok`) or a hard error.
async fn pump_sock_to_ziti<R>(sock_r: &mut R, zw: &mut EdgeWriteHalf) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; PROXY_BUF];
    loop {
        let n = sock_r.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // socket EOF
        }
        zw.write(&buf[..n]).await.map_err(io::Error::other)?;
    }
}

/// ziti→socket: copy ziti `read` chunks (deframed + decrypted) into the socket. Returns on ziti
/// EOF (`Ok(None)`) or a hard error.
async fn pump_ziti_to_sock<W>(zr: &mut EdgeReadHalf, sock_w: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        match zr.read().await {
            Ok(Some(bytes)) => sock_w.write_all(&bytes).await?,
            Ok(None) => return Ok(()), // ziti EOF
            Err(e) => return Err(io::Error::other(e)),
        }
    }
}

/// Run a proxy-TCP listener: accept TCP connections and splice each onto a freshly dialed ziti
/// `service` connection. One spliced connection per accept, handled concurrently.
///
/// Runs each connection under `tokio::task::spawn_local` (so it MUST be driven inside a
/// `tokio::task::LocalSet`): `EdgeClient::connect` is `!Send` (since slice 10c), so the per-conn
/// work cannot move across threads. A failed dial is logged and the listener keeps accepting (a
/// down service does not kill the proxy).
///
/// Conscious deviation: if `accept` errors, this returns and the driving `LocalSet` drops, which
/// aborts any in-flight per-connection splices. The oracle's `DialAndRun` goroutines are decoupled
/// from the accept loop, so established connections survive an accept error there. Acceptable for a
/// proxy whose lifetime is the listener's (an `accept` error is effectively a shutdown signal).
///
/// # Errors
/// Returns an `io::Error` only if the listener's `accept` fails (the loop otherwise never returns).
pub async fn run_tcp_proxy(
    client: Rc<EdgeClient>,
    listener: TcpListener,
    service: String,
) -> io::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let client = Rc::clone(&client);
        let service = service.clone();
        tokio::task::spawn_local(async move {
            handle_conn(&client, &service, sock, peer).await;
        });
    }
}

/// Dial `service`, splice `sock` onto it, then release the SHARED channel handle. Holds the channel
/// `Arc` in scope across the splice so its rx-loop keeps feeding the read half.
///
/// HOL-coupling (pool slice): since proxy conns to the same router now share ONE rx-loop, a slow
/// downstream socket that lets a conn's bounded inbound queue fill backpressure-parks the shared
/// rx-loop, briefly HOL-stalling sibling conns until they drain (or, in the limit, until the latency
/// probe tears the channel down after ~one interval). This is FAITHFUL — it ports the oracle channel
/// rxer's single sequenced reader (`PutSequenced`, seq.go:51-57, no drop arm); the pre-pool
/// one-conn-per-channel model was over-isolated relative to the oracle.
async fn handle_conn(client: &EdgeClient, service: &str, sock: TcpStream, peer: SocketAddr) {
    match client.connect(service).await {
        Ok(svc) => {
            let (zr, zw, channel) = svc.into_parts();
            let res = splice(zr, zw, sock).await;
            // The conn-level full-close (StateClosed + deregister this conn-id) already happened
            // inside `splice` (`zw.close()`). Do NOT close the CHANNEL: since the pool slice it is a
            // SHARED `Arc<EdgeChannel>` that the connection pool owns and keeps for reuse — a sibling
            // proxy conn may ride the same channel. Our `Arc` clone just drops here (the rx-loop is
            // aborted only when the LAST `Arc`, the pool's included, drops). Was a force-close in the
            // one-conn-per-channel model.
            drop(channel);
            if let Err(e) = res {
                tracing::warn!(error = %e, %peer, "proxy: connection ended with error");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, %peer, service = %service, "proxy: ziti connect failed");
        }
    }
}

/// Parse one `<service>:<port>` mapping of `noa proxy-multi` (same shape as the oracle CLI's
/// `ziti tunnel proxy <service>:<port>...`). Splits on the LAST `:` so a service name that itself
/// contains `:` still parses; the port must be a non-zero `u16`.
///
/// # Errors
/// A human-readable message if the spec has no `:`, an empty service name or an invalid port.
pub fn parse_service_port(spec: &str) -> Result<(String, u16), String> {
    let (service, port) = spec
        .rsplit_once(':')
        .ok_or_else(|| format!("'{spec}': se esperaba <servicio>:<puerto>"))?;
    if service.is_empty() {
        return Err(format!("'{spec}': nombre de servicio vacío"));
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok((service.to_string(), p)),
        _ => Err(format!("'{spec}': puerto inválido '{port}'")),
    }
}

/// Run one [`run_tcp_proxy`] accept loop per `(listener, service)` binding, all sharing ONE
/// authenticated `client` (one identity, one API session, one connection pool), like the oracle's
/// multi-service `ziti tunnel proxy`. MUST be driven inside a `tokio::task::LocalSet` (see
/// [`run_tcp_proxy`]).
///
/// Returns as soon as ANY listener's loop ends: a proxy that silently lost one of its services is
/// worse than one that exits and gets restarted by its supervisor (the Kubernetes Deployment of the
/// in-cluster dialer). Dropping the set aborts the remaining loops.
///
/// # Errors
/// The first listener `accept` error.
pub async fn run_tcp_proxies(
    client: Rc<EdgeClient>,
    bindings: Vec<(TcpListener, String)>,
) -> io::Result<()> {
    let mut set = tokio::task::JoinSet::new();
    for (listener, service) in bindings {
        set.spawn_local(run_tcp_proxy(Rc::clone(&client), listener, service));
    }
    match set.join_next().await {
        Some(Ok(res)) => res,
        Some(Err(e)) => Err(io::Error::other(e)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::connect::read_message;
    use crate::channel::message::Message;
    use crate::edge::data::{ChannelState, EdgeConn};
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS, build_data};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const TEST_CONN_ID: u32 = 7;

    fn flags_of(msg: &Message) -> u32 {
        msg.headers
            .get(&HDR_FLAGS)
            .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()))
    }

    fn fin_frame() -> Message {
        let mut fin = build_data(TEST_CONN_ID, b"", false);
        fin.headers
            .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
        fin
    }

    /// A fake ziti connection split into halves, with: a `state` handle to assert deregister; a
    /// `data_tx` to INJECT inbound (ziti→socket) frames (no rx-loop in the test); and the router-side
    /// duplex end that carries the frames the splice WRITES to ziti (socket→ziti + FIN + StateClosed).
    fn fake_conn() -> (
        EdgeReadHalf,
        EdgeWriteHalf,
        Arc<ChannelState>,
        mpsc::Sender<Message>,
        tokio::io::DuplexStream,
    ) {
        let (cw, router) = tokio::io::duplex(64 * 1024);
        let state = Arc::new(ChannelState::new(Box::new(cw)));
        let (data_tx, data_rx) = mpsc::channel(64);
        state.register_conn(TEST_CONN_ID, data_tx.clone());
        let conn = EdgeConn::new_for_test(TEST_CONN_ID, data_rx, state.clone());
        let (zr, zw) = conn.into_split();
        (zr, zw, state, data_tx, router)
    }

    /// Full happy path: bytes flow BOTH ways through the splice; a local socket half-close is
    /// forwarded to ziti as exactly one FIN frame; the peer's FIN ends the ziti→socket direction;
    /// after both directions finish, the splice does the single full-close (StateClosed) and
    /// deregisters the conn from the mux. This is the load-bearing test for the oracle's
    /// Run/myCopy semantics.
    #[tokio::test]
    async fn splice_round_trips_bytes_propagates_half_close_then_deregisters() {
        let (zr, zw, state, data_tx, mut router) = fake_conn();
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);

        // Fake ziti echo peer: echo Data bodies back inbound; on the splice's FIN, echo a FIN back
        // (peer half-close) and stop echoing; record whether we saw the final StateClosed.
        let echo = tokio::spawn(async move {
            let mut saw_fin = false;
            let mut saw_state_closed = false;
            loop {
                let Ok(msg) = read_message(&mut router).await else {
                    break;
                };
                match msg.content_type {
                    CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {
                        saw_fin = true;
                        let _ = data_tx.send(fin_frame()).await; // peer half-closes back
                    }
                    CT_DATA => {
                        let echoed = build_data(TEST_CONN_ID, &msg.body, false);
                        if data_tx.send(echoed).await.is_err() {
                            break;
                        }
                    }
                    CT_STATE_CLOSED => {
                        saw_state_closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            (saw_fin, saw_state_closed)
        });

        let splice_fut = splice(zr, zw, sock_for_splice);
        let client_fut = async {
            local.write_all(b"hello-proxy").await.unwrap();
            let mut buf = [0u8; 11];
            local.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-proxy", "bytes round-trip through the splice");
            local.shutdown().await.unwrap(); // socket half-close -> FIN to ziti -> peer FIN -> ziti EOF
            let mut rest = Vec::new();
            local.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "no extra bytes after the echo");
        };

        let (sres, ()) = tokio::join!(splice_fut, client_fut);
        sres.expect("splice completes cleanly");
        let (saw_fin, saw_state_closed) = echo.await.unwrap();
        assert!(
            saw_fin,
            "socket half-close forwarded as a FIN frame to ziti"
        );
        assert!(
            saw_state_closed,
            "splice sent StateClosed (full close) after both directions ended"
        );
        assert_eq!(
            state.conn_count(),
            0,
            "the conn was deregistered from the mux exactly once"
        );
    }

    /// A ziti-initiated EOF (inbound FIN, no data) half-closes the socket: the local read sees EOF.
    /// The socket→ziti direction then EOFs when the local end closes, and the splice tears down.
    #[tokio::test]
    async fn splice_ziti_eof_half_closes_the_socket() {
        let (zr, zw, state, data_tx, mut router) = fake_conn();
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);

        // ziti peer: send a FIN inbound immediately (ziti EOF), then drain the splice's writes so
        // its close_write/close succeed (and the conn is deregistered). Stop on StateClosed.
        data_tx.send(fin_frame()).await.unwrap();
        let drain = tokio::spawn(async move {
            // keep data_tx alive so the registered mux sender does not look dropped
            let _keep = data_tx;
            while let Ok(msg) = read_message(&mut router).await {
                if msg.content_type == CT_STATE_CLOSED {
                    break;
                }
            }
        });

        let splice_fut = splice(zr, zw, sock_for_splice);
        let client_fut = async {
            // ziti sent only EOF -> the splice shuts the socket write -> our read sees EOF.
            let mut buf = Vec::new();
            local.read_to_end(&mut buf).await.unwrap();
            assert!(buf.is_empty(), "ziti EOF with no data -> socket sees EOF");
            local.shutdown().await.unwrap(); // close our side so socket->ziti EOFs too
        };

        let (sres, (), dres) = tokio::join!(splice_fut, client_fut, drain);
        sres.expect("splice completes");
        dres.unwrap();
        assert_eq!(state.conn_count(), 0, "deregistered after teardown");
    }

    /// A socket whose reads are immediate EOF and whose writes always hard-error. Drives the
    /// error path of the ziti→socket direction (oracle myCopy: error is logged, NOT propagated to
    /// abort the peer direction).
    #[derive(Default)]
    struct ErrWriteSocket;

    impl tokio::io::AsyncRead for ErrWriteSocket {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(())) // leave buf unfilled -> read() == Ok(0) == EOF
        }
    }

    impl tokio::io::AsyncWrite for ErrWriteSocket {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "boom")))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A HARD ERROR in one direction (here ziti→socket write fails) must NOT abort the peer
    /// direction: the splice waits for BOTH (join!, not try_join!), the peer (socket→ziti) still
    /// runs its half-close (FIN), the error surfaces from the splice, and the conn is still
    /// deregistered exactly once. Mirrors the oracle's myCopy (error logged, not propagated). A
    /// `join!`→`try_join!` mutation would make this RED while the happy-path tests stay green.
    #[tokio::test]
    async fn splice_hard_error_one_direction_does_not_abort_peer_and_still_closes() {
        let (zr, zw, state, data_tx, mut router) = fake_conn();
        // Give ziti data so the ziti->socket direction attempts a (failing) socket write.
        data_tx
            .send(build_data(TEST_CONN_ID, b"payload", false))
            .await
            .unwrap();

        let drain = tokio::spawn(async move {
            let _keep = data_tx; // keep the mux sender alive
            let mut saw_fin = false;
            let mut saw_state_closed = false;
            while let Ok(msg) = read_message(&mut router).await {
                match msg.content_type {
                    CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
                    CT_STATE_CLOSED => {
                        saw_state_closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            (saw_fin, saw_state_closed)
        });

        let res = splice(zr, zw, ErrWriteSocket).await;

        assert!(
            res.is_err(),
            "the ziti->socket write error surfaces from the splice"
        );
        let (saw_fin, saw_state_closed) = drain.await.unwrap();
        assert!(
            saw_fin,
            "the PEER direction (socket->ziti) still ran its half-close (FIN) despite the other direction erroring"
        );
        assert!(
            saw_state_closed,
            "the single full-close (StateClosed) still ran after both directions ended"
        );
        assert_eq!(
            state.conn_count(),
            0,
            "deregistered exactly once even on a hard error"
        );
    }

    #[test]
    fn parse_service_port_accepts_oracle_shape() {
        assert_eq!(
            parse_service_port("git-http:3000"),
            Ok(("git-http".into(), 3000))
        );
        assert_eq!(parse_service_port("a:b:2222"), Ok(("a:b".into(), 2222)));
    }

    #[test]
    fn parse_service_port_rejects_malformed() {
        for bad in ["git-http", ":3000", "svc:", "svc:0", "svc:70000", "svc:x"] {
            assert!(parse_service_port(bad).is_err(), "{bad} debería rechazarse");
        }
    }
}
