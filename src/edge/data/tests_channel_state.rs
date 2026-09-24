//! Split test module (F6 tramo 1b), byte-identical bodies.
use super::testsupport::*;
use super::*;

#[traced_test]
#[tokio::test]
async fn update_token_succeeds_on_update_token_success() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let ut = read_message(&mut router).await.unwrap();
        assert_eq!(ut.content_type, CT_UPDATE_TOKEN, "ct 60803");
        assert_eq!(ut.body, b"new-bearer", "body = the rotated token bytes");
        assert!(ut.headers.is_empty(), "no headers");
        // Reply UpdateTokenSuccess, correlated by ReplyFor = the request sequence.
        let mut ok = Message::new(CT_UPDATE_TOKEN_SUCCESS, vec![]);
        ok.headers
            .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &ok).await.unwrap();
    });

    ch.update_token("new-bearer", Duration::from_secs(5))
        .await
        .expect("UpdateTokenSuccess => Ok");
    router_task.await.unwrap();
}

#[tokio::test]
async fn update_token_returns_failure_reason_on_update_token_failure() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let ut = read_message(&mut router).await.unwrap();
        assert_eq!(ut.content_type, CT_UPDATE_TOKEN);
        let mut fail = Message::new(CT_UPDATE_TOKEN_FAILURE, b"token rejected".to_vec());
        fail.headers
            .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &fail).await.unwrap();
    });

    let err = ch
        .update_token("new-bearer", Duration::from_secs(5))
        .await
        .expect_err("UpdateTokenFailure => Err");
    match err {
        EdgeError::UpdateTokenFailed { reason } => {
            assert_eq!(
                reason, "token rejected",
                "reason = the failure body verbatim"
            );
        }
        other => panic!("expected UpdateTokenFailed, got {other:?}"),
    }
    router_task.await.unwrap();
}

#[tokio::test]
async fn update_token_rejects_unexpected_content_type() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let ut = read_message(&mut router).await.unwrap();
        // Reply with a wholly unexpected content type, still correlated by ReplyFor.
        let mut weird = Message::new(CT_DATA, vec![]);
        weird
            .headers
            .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &weird).await.unwrap();
    });

    let err = ch
        .update_token("new-bearer", Duration::from_secs(5))
        .await
        .expect_err("an unexpected content type => Err");
    match err {
        EdgeError::UpdateTokenFailed { reason } => {
            assert!(
                reason.contains("invalid content type"),
                "reason mentions the invalid content type, got: {reason}"
            );
        }
        other => panic!("expected UpdateTokenFailed, got {other:?}"),
    }
    router_task.await.unwrap();
}

/// A router that reads the push but NEVER replies must NOT hang `update_token`: the 10s budget
/// (injected short here) bounds it. MUTATION: drop the `tokio::time::timeout` in `update_token` and
/// this test hangs forever → RED. The wall-clock assertion proves the bound fired (not a real wait).
#[tokio::test]
async fn update_token_times_out_when_router_never_replies() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    // Keep the router alive (reading) but never reply — the channel stays open so the failure is the
    // timeout, not a ChannelClosed.
    let router_task = tokio::spawn(async move {
        let _ut = read_message(&mut router).await.unwrap();
        // Hold the read half so the duplex does not close; sleep beyond the test budget.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(router);
    });

    let budget = Duration::from_millis(150);
    let start = std::time::Instant::now();
    let err = ch
        .update_token("new-bearer", budget)
        .await
        .expect_err("a non-responding router must trip the update-token timeout");
    let elapsed = start.elapsed();
    assert!(
        matches!(err, EdgeError::UpdateTokenFailed { .. }),
        "expected UpdateTokenFailed (timeout), got {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the budget must bound the wall-clock (got {elapsed:?})"
    );
    router_task.abort();
}

#[tokio::test]
async fn rx_loop_routes_data_to_registered_conn() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(1, tx);
    let mut conn = EdgeConn::new_for_test(1, rx, state.clone());

    // router sends a Data frame for conn 1
    let mut data = Message::new(CT_DATA, b"pong".to_vec());
    data.headers
        .insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &data).await.unwrap();

    assert_eq!(conn.read().await.unwrap(), Some(b"pong".to_vec()));
    drop(router); // EOF -> rx-loop exits
    let _ = task.await;
}

// ----------------------------------------------------------------------------------------------
// Latency probe / close-notify (fix HOL-stall-masks-death). See
// docs/superpowers/specs/2026-06-27-rxloop-latency-probe-close-notify-design.md
// ----------------------------------------------------------------------------------------------

/// THE bug (finding #3): a healthy sibling must EOF when the router dies, EVEN WHILE another sibling
/// HOL-stalls the rx-loop. Death is injected as a write-error path: the rx-loop is parked dispatching
/// to the stalled sibling (so it never observes the read EOF), and the latency probe — the
/// INDEPENDENT detector — finds the dead transport (its probe write fails) and tears the channel
/// down. Wrapped in a `timeout` so the ORIGINAL bug surfaces as a FAILURE, not a hung suite.
#[tokio::test]
async fn healthy_sibling_eofs_on_death_despite_a_stalled_sibling() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
            Duration::from_millis(60),
            Duration::from_millis(60),
        );
        // Conn A: stalled. Hold `_a_rx` so the queue exists but is NEVER drained.
        let (a_tx, _a_rx) = mpsc::channel(4);
        ch.state.register_conn(1, a_tx);
        // Conn B: healthy. We read it.
        let (b_tx, b_rx) = mpsc::channel(4);
        ch.state.register_conn(2, b_tx);
        let mut conn_b = EdgeConn::new_for_test(2, b_rx, ch.state.clone());

        stall_rx_loop_on(&mut router, 1).await;
        // Router death: drop the duplex end. The channel's read EOFs and its writes break, but the
        // rx-loop is parked on the dispatch to A — only the probe can detect this.
        drop(router);

        // Without the fix this hangs forever.
        assert_eq!(
            conn_b.read().await.unwrap(),
            None,
            "healthy sibling must EOF on channel death even with a stalled sibling"
        );
    })
    .await
    .expect("a stalled sibling must not mask channel death from a healthy sibling (deadlock)");
}

/// The read-idle teardown path: the router stays ALIVE (drains our writes) but never replies to the
/// probe, while a sibling HOL-stalls the rx-loop. The probe's reply times out and — because no frame
/// has been read for longer than the interval — it closes the channel (faithful: the oracle's single
/// rxer is starved the same way and `GetTimeSinceLastRead()` fires). A healthy sibling EOFs.
#[tokio::test]
async fn healthy_sibling_eofs_on_readidle_timeout_with_silent_router() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
            Duration::from_millis(60),
            Duration::from_millis(60),
        );
        let (a_tx, _a_rx) = mpsc::channel(4);
        ch.state.register_conn(1, a_tx);
        let (b_tx, b_rx) = mpsc::channel(4);
        ch.state.register_conn(2, b_tx);
        let mut conn_b = EdgeConn::new_for_test(2, b_rx, ch.state.clone());

        stall_rx_loop_on(&mut router, 1).await;
        // Router stays alive but silent: drain our writes (so the probe write succeeds) and never
        // reply. The probe times out, sees read-idle, and closes.
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match tokio::io::AsyncReadExt::read(&mut router, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {} // discard (incl. the probe) — never reply
                }
            }
        });

        assert_eq!(
            conn_b.read().await.unwrap(),
            None,
            "healthy sibling must EOF when the probe times out on a read-idle stalled channel"
        );
        drop(ch);
        let _ = drain.await;
    })
    .await
    .expect("read-idle timeout must tear down a stalled channel (deadlock)");
}

/// The probe must NOT false-close a live, responding channel. An otherwise-idle channel whose router
/// answers the latency probe survives past several intervals, and a healthy conn still delivers data
/// the router sends afterwards. This is the unit mirror of the live "idle channel survives ≥1 probe
/// interval" assertion (proves the GUARD: traffic generation keeps `last_read` fresh).
#[tokio::test]
async fn responding_router_keeps_idle_channel_alive() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
            Duration::from_millis(40),
            Duration::from_millis(40),
        );
        let (b_tx, b_rx) = mpsc::channel(4);
        ch.state.register_conn(9, b_tx);
        let mut conn_b = EdgeConn::new_for_test(9, b_rx, ch.state.clone());

        // Router: reply to every latency probe (Result with ReplyFor = the probe's sequence), then
        // after a few intervals send a Data frame to conn 9 to prove the channel is still wired.
        // Counts probes so the test is non-vacuous (proves the probe actually fired on the wire).
        let router_task = tokio::spawn(async move {
            let mut probes = 0u32;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
            while tokio::time::Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_millis(50), read_message(&mut router))
                    .await
                {
                    Ok(Ok(req)) if req.content_type == CT_LATENCY => {
                        probes += 1;
                        let mut resp = Message::new(CT_RESULT, Vec::new());
                        resp.headers
                            .insert(MSG_HDR_REPLY_FOR, req.sequence.to_le_bytes().to_vec());
                        write_message(&mut router, &resp).await.unwrap();
                    }
                    _ => {}
                }
            }
            // Channel must still be alive: deliver a Data frame to conn 9.
            let mut d = Message::new(CT_DATA, b"alive".to_vec());
            d.headers.insert(HDR_CONN_ID, 9u32.to_le_bytes().to_vec());
            write_message(&mut router, &d).await.unwrap();
            (probes, router) // keep the end alive
        });

        assert_eq!(
            conn_b.read().await.unwrap(),
            Some(b"alive".to_vec()),
            "a responding router must keep an idle channel alive past several probe intervals"
        );
        assert!(
            !ch.state.closed.load(Ordering::Acquire),
            "the channel must not be closed while the router answers probes"
        );
        let (probes, _router) = router_task.await.unwrap();
        assert!(
            probes >= 1,
            "the probe must have fired on the wire (saw {probes} latency frames)"
        );
    })
    .await
    .expect("a responding router must keep the channel alive (unexpected close)");
}

// ----- latency scoring accumulator (slice scoring (A)) -----

/// The per-channel latency accumulator is a running mean (`sum/count`); an unsampled channel reads
/// `u64::MAX` so it sorts LAST in the pool's lowest-mean pick. Pure unit on `ChannelState`.
#[tokio::test]
async fn latency_accumulator_is_a_running_mean_unsampled_is_max() {
    let (w, _r) = tokio::io::duplex(64);
    let state = ChannelState::new(Box::new(w));
    assert_eq!(state.latency_sample_count(), 0);
    assert_eq!(
        state.mean_latency_nanos(),
        u64::MAX,
        "an unsampled channel sorts last"
    );
    state.record_latency(100);
    state.record_latency(300);
    assert_eq!(state.latency_sample_count(), 2);
    assert_eq!(
        state.mean_latency_nanos(),
        200,
        "running mean of 100 and 300 is 200"
    );
}

/// A latency-probe REPLY records the round-trip time into the scoring accumulator (mirror of the
/// oracle's `ResultHandler(resultNanos)`, `ziti.go:1890`). RED if the Alive branch of
/// `send_latency_probe` drops the `record_latency` call.
#[tokio::test]
async fn responding_probe_records_a_latency_sample() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
            Duration::from_millis(40),
            Duration::from_millis(40),
        );
        // Router answers every latency probe (Result + ReplyFor) so each round records an RTT sample.
        let router_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(req)) =
                    tokio::time::timeout(Duration::from_millis(50), read_message(&mut router)).await
                    && req.content_type == CT_LATENCY
                {
                    let mut resp = Message::new(CT_RESULT, Vec::new());
                    resp.headers
                        .insert(MSG_HDR_REPLY_FOR, req.sequence.to_le_bytes().to_vec());
                    let _ = write_message(&mut router, &resp).await;
                }
            }
            router
        });
        // Wait for at least one probe round (sleep 40ms + reply) to record a sample.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if ch.state.latency_sample_count() >= 1 {
                break;
            }
        }
        assert!(
            ch.state.latency_sample_count() >= 1,
            "a probe reply must record a latency sample"
        );
        let mean = ch.state.mean_latency_nanos();
        assert!(
            mean > 0 && mean < u64::MAX,
            "the recorded RTT is a finite positive mean (got {mean})"
        );
        let _router = router_task.await.unwrap();
    })
    .await
    .expect("a responding probe must record a latency sample");
}

/// A slow-but-not-dead probe (timeout WITH recent read progress) records the full timeout as a
/// penalty sample and keeps the channel ALIVE — the oracle's `TimeoutHandler` else-branch
/// `h.Update(int64(LatencyCheckTimeout))` (`ziti.go:1903`). RED if the not-idle branch of
/// `run_latency_probe` drops the `record_latency` call. The router NEVER replies to the probe (so
/// every sample is a penalty → the mean equals the timeout exactly), but keeps the channel
/// read-busy with Data frames so the death branch (read-idle close) does not fire.
#[tokio::test]
async fn slow_probe_records_timeout_penalty_and_stays_alive() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let interval = Duration::from_millis(30);
        let timeout = Duration::from_millis(50);
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
            interval,
            timeout,
        );
        let (b_tx, b_rx) = mpsc::channel(8);
        ch.state.register_conn(9, b_tx);
        let mut conn_b = EdgeConn::new_for_test(9, b_rx, ch.state.clone());

        // Router: NEVER reply to probes, but send a Data frame to conn 9 every ~15ms so the channel
        // is never read-idle → the probe times out into the PENALTY branch, not the death branch.
        let router_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
            while tokio::time::Instant::now() < deadline {
                let mut d = Message::new(CT_DATA, b"x".to_vec());
                d.headers.insert(HDR_CONN_ID, 9u32.to_le_bytes().to_vec());
                if write_message(&mut router, &d).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            router
        });
        // Drain conn 9 so the rx-loop never HOL-stalls (so it keeps reading → last_read stays fresh).
        let drain = tokio::spawn(async move { while let Ok(Some(_)) = conn_b.read().await {} });

        let mut count = 0;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            count = ch.state.latency_sample_count();
            if count >= 1 {
                break;
            }
        }
        assert!(
            count >= 1,
            "a slow-but-not-dead probe records a timeout penalty (count={count})"
        );
        assert!(
            !ch.state.closed.load(Ordering::Acquire),
            "a non-idle channel must NOT be closed by a slow probe"
        );
        assert_eq!(
            ch.state.mean_latency_nanos(),
            u64::try_from(timeout.as_nanos()).unwrap(),
            "every penalty sample is the full probe timeout"
        );
        drain.abort();
        let _router = router_task.await.unwrap();
    })
    .await
    .expect("a slow probe must record the timeout penalty without closing the channel");
}

/// `close_notify` is load-bearing: it releases a rx-loop parked on a backpressured per-conn dispatch
/// so the loop can exit. Clearing the maps does NOT release it (the loop holds a *clone* of the
/// stalled conn's sender). Without the close-notify arm in the dispatch this `rx_task.await` hangs
/// forever — the distinct job the healthy-sibling tests (covered by the map-clear) do NOT exercise.
#[tokio::test]
async fn mark_closed_releases_a_dispatch_stalled_rx_loop() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let state = Arc::new(ChannelState::new(Box::new(cw)));
        let rx_task = tokio::spawn(rx_loop(Box::new(cr), state.clone()));
        let (a_tx, _a_rx) = mpsc::channel(4); // stalled: never drained
        state.register_conn(1, a_tx);
        stall_rx_loop_on(&mut router, 1).await;

        // The rx-loop is now parked dispatching to A. Closing must release it.
        state.mark_closed();
        rx_task
            .await
            .expect("rx-loop task should have exited cleanly");
    })
    .await
    .expect("mark_closed must release a dispatch-stalled rx-loop (it would otherwise leak parked)");
}

/// `is_alive()` must mirror the oracle's `IsClosed()` (= `state.closed`), NOT merely whether the
/// `rx_task` JoinHandle has finished. The latency probe's death paths (a black-hole router's
/// read-idle timeout, and a wedged-send `WriteError`) call `mark_closed()` WITHOUT aborting the
/// rx-loop — it stays parked on `read_message` of a transport that never EOFs, so its JoinHandle
/// reports STILL-RUNNING. The router connection pool trusts `is_alive()` for lazy eviction, so a
/// `rx_task`-only predicate would re-hand-out this probe-killed channel. Pin it: a black-hole channel
/// that has been `mark_closed` reports `!is_alive()` while its rx-task is still parked. RED under the
/// `rx_task`-only predicate (the bug this fix closes).
#[tokio::test]
async fn marked_closed_black_hole_channel_is_not_alive_despite_parked_rx_task() {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    // The router end is held open forever (never sends, never EOFs) → the rx-loop parks on
    // `read_message` and the 30s probe never fires within the test.
    let _router_guard = router_io;
    assert!(
        ch.is_alive(),
        "a fresh channel with a running rx-loop is alive"
    );

    // Simulate the latency probe declaring death (its read-idle/WriteError close): `mark_closed`
    // sets `closed` + clears the maps, but does NOT abort the parked rx-task.
    ch.state.mark_closed();
    assert!(
        ch.rx_task.as_ref().is_some_and(|t| !t.is_finished()),
        "precondition: the rx-task is STILL parked on read_message (no EOF, not aborted)"
    );
    assert!(
        !ch.is_alive(),
        "a mark_closed (probe-killed) channel must report dead even while its rx-task is parked — \
             is_alive mirrors IsClosed (state.closed), not just rx_task.is_finished()"
    );
}

/// `mark_closed` is idempotent and does BOTH jobs: it clears the mux maps (EOFing a parked reader)
/// and fires `close_notify`. Here we assert the reader-EOF effect directly.
#[tokio::test]
async fn mark_closed_clears_maps_and_is_idempotent() {
    let (client, _router) = tokio::io::duplex(64);
    let (cr, cw) = tokio::io::split(client);
    drop(cr);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(5, tx);
    let mut conn = EdgeConn::new_for_test(5, rx, state.clone());

    state.mark_closed();
    assert!(state.conns.lock().unwrap().is_empty(), "maps cleared");
    assert!(state.closed.load(Ordering::Acquire));
    // The parked reader sees EOF (its sender was dropped by the map clear).
    assert_eq!(
        conn.read().await.unwrap(),
        None,
        "reader EOFs after mark_closed"
    );
    // Idempotent: a second call is a no-op and does not panic.
    state.mark_closed();
    assert!(state.closed.load(Ordering::Acquire));
}

/// F1 (review-required): the probe's SEND (lock acquire + write) is timeout-bounded, so a black-holed
/// transport write still tears the channel down (and a healthy sibling EOFs). Without the bound the
/// probe would park forever on the write, re-introducing the very hang this slice fixes.
#[tokio::test]
async fn probe_bounded_send_tears_down_on_write_blackhole() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, router) = tokio::io::duplex(8192);
        let (cr, _cw) = tokio::io::split(client);
        // read half stays open (hold `router`, write nothing → no EOF); write half is a black hole.
        let ch = EdgeChannel::from_halves_with_probe(
            Box::new(cr),
            Box::new(BlackHoleWrite),
            std::collections::BTreeMap::new(),
            Duration::from_millis(40),
            Duration::from_millis(40),
        );
        let _router = router;
        let (b_tx, b_rx) = mpsc::channel(4);
        ch.state.register_conn(7, b_tx);
        let mut conn_b = EdgeConn::new_for_test(7, b_rx, ch.state.clone());

        // probe fires ~40ms, write blocks, bounded send times out ~80ms → WriteError → mark_closed.
        assert_eq!(
            conn_b.read().await.unwrap(),
            None,
            "a black-holed probe write must still tear the channel down via the bounded send"
        );
    })
    .await
    .expect("the latency probe's send must be timeout-bounded (else a write black-hole hangs)");
}

/// C5 (review): a conn registered AFTER the channel is closing is a no-op — its `tx` is dropped, so
/// the conn EOFs immediately instead of orphaning (its `read()` would otherwise hang on a live tx
/// stranded in a cleared map).
#[tokio::test]
async fn register_conn_after_close_is_a_noop_and_conn_eofs() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, _router) = tokio::io::duplex(64);
        let (cr, cw) = tokio::io::split(client);
        drop(cr);
        let state = Arc::new(ChannelState::new(Box::new(cw)));
        state.mark_closed();
        let (tx, rx) = mpsc::channel(4);
        state.register_conn(3, tx);
        assert!(
            state.conns.lock().unwrap().is_empty(),
            "register on a closing channel must not insert"
        );
        let mut conn = EdgeConn::new_for_test(3, rx, state.clone());
        assert_eq!(
            conn.read().await.unwrap(),
            None,
            "a conn registered after close EOFs immediately"
        );
    })
    .await
    .expect("register-after-close must not orphan the conn");
}

#[tokio::test]
async fn rx_loop_routes_dial_to_registered_bind() {
    let (state, task, mut router) = rig();
    let (tx, mut rx) = mpsc::channel(4);
    state.register_bind(7, tx);

    // router sends a Dial addressed to bind conn 7
    let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec());
    dial.headers
        .insert(HDR_CONN_ID, 7u32.to_le_bytes().to_vec());
    write_message(&mut router, &dial).await.unwrap();

    let got = rx.recv().await.unwrap();
    assert_eq!(got.content_type, crate::edge::bind::CT_DIAL);
    assert_eq!(got.body, b"tok");
    drop(router);
    let _ = task.await;
}

#[tokio::test]
async fn rx_loop_routes_bind_state_closed_to_bind_queue() {
    let (state, task, mut router) = rig();
    let (tx, mut rx) = mpsc::channel(4);
    state.register_bind(7, tx);
    // No child conn registered for id 7 => StateClosed(conn 7) goes to the bind queue.
    let mut sc = Message::new(CT_STATE_CLOSED, vec![]);
    sc.headers.insert(HDR_CONN_ID, 7u32.to_le_bytes().to_vec());
    write_message(&mut router, &sc).await.unwrap();

    let got = rx.recv().await.unwrap();
    assert_eq!(got.content_type, CT_STATE_CLOSED);
    drop(router);
    let _ = task.await;
}

// ───────────────── qw-wire-header-len: longitud EXACTA de los headers enteros ─────────────────

/// `T-2` (falsador de `C-1`, la cara del ENRUTADO). Un `Data` cuyo `ConnId` mide 5 bytes se
/// DESCARTA: `header_u32` da `None` y el rx-loop cae en su `continue` de «no conn id»
/// (`rxloop.rs:43-45`, la rama que ya existía para el header ausente). Es el observable del oráculo,
/// que con `len(encoded) != 4` devuelve `(0, false)` y su `HandleReceive` retorna sin enrutar
/// (`sdk-golang@4b6a087 ziti/edge/msg_mux.go:359-366`).
///
/// El negativo va ACREDITADO (RB-2): detrás del frame mal formado viaja un frame de SINCRONIZACIÓN
/// bien formado para la MISMA conn. Ver llegar el `b"sync"` como PRIMER `read()` prueba a la vez que
/// el mal formado se descartó y que el rx-loop siguió vivo — más fuerte que un timeout, que se
/// satisface también si el loop muere.
///
/// MUTACIÓN ASESINA: `v.len() >= 4` en `header_u32` ⇒ el prefijo `[1,0,0,0]` trunca a la conn 1 y el
/// PRIMER `read()` devuelve `Some(b"trunc")`.
#[tokio::test]
async fn rx_loop_drops_data_when_conn_id_header_is_five_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, rx) = mpsc::channel(4);
        state.register_conn(1, tx);
        let mut conn = EdgeConn::new_for_test(1, rx, state.clone());

        // (1) el frame BAJO PRUEBA: ConnId de 5 bytes cuyo prefijo LE es 1u32 (la conn registrada).
        let mut trunc = Message::new(CT_DATA, b"trunc".to_vec());
        trunc.headers.insert(HDR_CONN_ID, vec![1u8, 0, 0, 0, 9]);
        write_message(&mut router, &trunc).await.unwrap();

        // (2) el frame de SINCRONIZACIÓN, bien formado, para la misma conn.
        let mut sync = Message::new(CT_DATA, b"sync".to_vec());
        sync.headers
            .insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
        write_message(&mut router, &sync).await.unwrap();

        assert_eq!(
            conn.read().await.unwrap(),
            Some(b"sync".to_vec()),
            "el ConnId de 5 bytes debe DESCARTARSE: lo primero que llega es el frame de sincronización"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-2: el rx-loop no entregó el frame de sincronización dentro del presupuesto");
}

/// `T-6` (falsador de `C-4`). Un `ReplyFor` de 5 bytes cuyo prefijo LE case con una
/// secuencia VIVA deja de correlar: `header_i32` da `None`, el frame NO despierta al waiter y cae al
/// despacho por conn/bind, donde —al no traer `ConnId`— se descarta (`rxloop.rs:35-45`). La respuesta
/// legítima posterior sí resuelve la espera.
///
/// Comprobación defensiva: la longitud del header se valida antes de usarlo para correlar; un valor
/// fuera de la anchura exacta de 4 bytes se rechaza y el frame se procesa como no correlado, sin
/// interrumpir el rx-loop. `None` es estrictamente MÁS restrictivo que el `>= 4` de antes. Que este
/// test COMPLETE (y la respuesta legítima resuelva la espera) acredita que el rx-loop sigue vivo.
///
/// La respuesta forjada es `UpdateTokenFailure`/`b"forged"` A PROPÓSITO: con un `UpdateTokenSuccess`
/// forjado, despertar al waiter daría `Ok(())` (`wire.rs:30`) — el MISMO observable que produce el
/// código correcto al resolver con la segunda respuesta — y la mutación NO mataría.
///
/// MUTACIÓN ASESINA: `v.len() >= 4` en `header_i32` ⇒ el waiter se despierta con la forjada y el
/// resultado es `Err(EdgeError::UpdateTokenFailed { reason: "forged" })`.
#[tokio::test]
async fn rx_loop_does_not_wake_waiter_when_reply_for_header_is_five_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
        );

        let router_task = tokio::spawn(async move {
            let ut = read_message(&mut router).await.unwrap();
            assert_eq!(ut.content_type, CT_UPDATE_TOKEN, "ct 60803");

            // (1) respuesta FORJADA: ReplyFor de 5 bytes con el sequence REAL como prefijo LE.
            let mut forged_reply_for = ut.sequence.to_le_bytes().to_vec();
            forged_reply_for.push(9);
            let mut forged = Message::new(CT_UPDATE_TOKEN_FAILURE, b"forged".to_vec());
            forged.headers.insert(HDR_REPLY_FOR, forged_reply_for);
            write_message(&mut router, &forged).await.unwrap();

            // (2) la respuesta LEGÍTIMA, bien formada.
            let mut ok = Message::new(CT_UPDATE_TOKEN_SUCCESS, vec![]);
            ok.headers
                .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
            write_message(&mut router, &ok).await.unwrap();
        });

        ch.update_token("new-bearer", Duration::from_secs(5))
            .await
            .expect("la respuesta forjada de 5 bytes NO debe resolver la espera: solo la legítima");
        router_task.await.unwrap();
    })
    .await
    .expect("T-6: update_token no se resolvió dentro del presupuesto");
}

// ───────────── qw-getnextid-clamp: el generador de conn-ids del oráculo (`GetNextId`) ─────────────

/// El golden capturado EJECUTANDO el oráculo (`tests/fixtures/getnextid_goldengen`). Se lee con
/// `include_str!` — mismo patrón y misma profundidad que `tests_inspect.rs:37`, que vive en este
/// mismo directorio: ningún test toca el disco en runtime.
const GETNEXTID_GOLDEN: &str = include_str!("../../../tests/fixtures/getnextid_golden.json");

/// Una celda del golden, deserializada con `serde_json` (ya en `[dependencies]`, `Cargo.toml:56`;
/// es de donde lo toma `tests_inspect.rs:44-45` — no hace falta tocar `Cargo.toml`).
struct GoldenCell {
    id: String,
    seed_next_id: u32,
    in_use: std::collections::HashSet<u32>,
    min_id: u32,
    max_id: u32,
    returned_id: u32,
    next_id_after: u32,
}

fn getnextid_golden_cells() -> Vec<GoldenCell> {
    let v: serde_json::Value =
        serde_json::from_str(GETNEXTID_GOLDEN).expect("el golden es JSON válido");
    v["cells"]
        .as_array()
        .expect("el golden trae un array `cells`")
        .iter()
        .map(|c| GoldenCell {
            id: c["id"].as_str().expect("id").to_string(),
            seed_next_id: u32::try_from(c["seed_next_id"].as_u64().expect("seed_next_id")).unwrap(),
            in_use: c["in_use"]
                .as_array()
                .expect("in_use")
                .iter()
                .map(|x| u32::try_from(x.as_u64().expect("in_use[i]")).unwrap())
                .collect(),
            min_id: u32::try_from(c["min_id"].as_u64().expect("min_id")).unwrap(),
            max_id: u32::try_from(c["max_id"].as_u64().expect("max_id")).unwrap(),
            returned_id: u32::try_from(c["returned_id"].as_u64().expect("returned_id")).unwrap(),
            next_id_after: u32::try_from(c["next_id_after"].as_u64().expect("next_id_after"))
                .unwrap(),
        })
        .collect()
}

/// `T-1` (`R-1`). El generador del port reproduce `GetNextId` (`ziti/edge/msg_mux.go:337-352`, pin
/// `4b6a087`) **celda a celda** sobre las 12 capturadas EJECUTANDO el oráculo.
///
/// El `expected` NO se teclea: sale del golden en las DOS direcciones (RB-6-ampliada), así que un
/// error simétrico impl+literal es imposible. `min_id`/`max_id` se comparan contra lo CAPTURADO del
/// mux, no contra las constantes del port (el port no puede pinearse contra sí mismo).
///
/// SUELO (RB-2): el contador de celdas VISTAS va DESPUÉS de los asserts del bucle — un golden
/// vaciado da ROJO, no verde por vacío.
///
/// MUTACIÓN ASESINA: intercambiar el orden de las ramas (i) y (ii) del bucle ⇒ muere la celda
/// **`C-13`**, que es la ÚNICA que las separa (`seed = MaxUint32-1`, `in_use = {MaxUint32}`: el
/// candidato está EN USO **y** FUERA DE RANGO a la vez). Con el orden REAL salta, el `Add` ENVUELVE
/// a `0`, que está libre y en rango ⇒ **0**; con el orden invertido rebobina a `minId` ⇒ **1**.
/// ⚠ `C-11` NO sirve como falsador de esto: da el mismo valor bajo los dos órdenes (lo midieron el
/// paso 4 y tres escépticos; la prosa anterior de este doc era VACUA).
#[test]
fn alloc_conn_id_matches_the_oracle_golden_cell_by_cell() {
    let cells = getnextid_golden_cells();
    let mut vistas = 0usize;
    for cell in &cells {
        let counter = AtomicU32::new(cell.seed_next_id);
        let in_use = cell.in_use.clone();
        let got = alloc_conn_id(&counter, cell.min_id, cell.max_id, |id| {
            in_use.contains(&id)
        });
        assert_eq!(
            got, cell.returned_id,
            "celda {}: el id devuelto no es el del oráculo",
            cell.id
        );
        assert_eq!(
            counter.load(Ordering::Relaxed),
            cell.next_id_after,
            "celda {}: el contador tras la llamada no es el del oráculo",
            cell.id
        );
        assert_eq!(cell.min_id, 0, "celda {}: minId CAPTURADO del mux", cell.id);
        assert_eq!(
            cell.max_id, 2_147_483_646,
            "celda {}: maxId CAPTURADO del mux",
            cell.id
        );
        vistas += 1;
    }
    assert_eq!(
        vistas, 13,
        "SUELO: el golden tiene 13 celdas; un golden vaciado no puede dar verde"
    );
}

/// `T-2` (`R-1`, rama (i) del bucle). Fixture MULTI-ELEMENTO con ORDEN DECLARADO: contador `0`,
/// `in_use = {1, 2}` ⇒ el primer candidato (1) falla, el segundo (2) falla, el tercero (3) pasa.
///
/// ⚠ ORDEN de los mundos DECLARADO: mundo A (`in_use={1,2}`) primero, mundo B (`in_use={}`) después.
/// Bajo una mutación que mate A, la supervivencia de B es INFERIDA, no medida.
///
/// MUTACIÓN ASESINA: borrar la rama (i) (`if in_use(next_id)`) ⇒ el mundo A devuelve `1`.
#[test]
fn alloc_conn_id_skips_ids_in_use_in_declared_order() {
    // Mundo A: dos en uso consecutivos (la rama (i) tiene que recorrerse DOS veces).
    let in_use: std::collections::HashSet<u32> = [1u32, 2u32].into_iter().collect();
    let counter = AtomicU32::new(0);
    let got = alloc_conn_id(&counter, MIN_CONN_ID, MAX_CONN_ID, |id| {
        in_use.contains(&id)
    });
    assert_eq!(got, 3, "mundo A: 1 y 2 en uso ⇒ el tercer candidato");
    assert_eq!(counter.load(Ordering::Relaxed), 3, "mundo A: contador en 3");

    // Mundo B: nada en uso ⇒ la rama «falso ⇒ retorna» desde el primer candidato.
    let counter_b = AtomicU32::new(0);
    let got_b = alloc_conn_id(&counter_b, MIN_CONN_ID, MAX_CONN_ID, |_| false);
    assert_eq!(
        got_b, 1,
        "mundo B: sin nada en uso el primer candidato vale"
    );
}

/// `T-3` (`R-1`, rama (ii) + celda `C-09`). Tabla de 4 mundos con ORDEN DECLARADO.
///
/// MUTACIONES ASESINAS (dos, SEPARADORAS): `next_id >= max_id` → `next_id > max_id` mata el mundo 2
/// (devolvería `2147483646`, fuera del rango del oráculo) y deja VIVO el mundo 1; `wrapping_add(1)`
/// → `+ 1` panica en el mundo 4 (`attempt to add with overflow`), con los mundos 1-3 ya pasados.
#[test]
fn alloc_conn_id_rewinds_at_the_max_id_frontier_and_wraps_the_counter() {
    // 1. lado A de la frontera: el ÚLTIMO id válido se DEVUELVE.
    let c1 = AtomicU32::new(2_147_483_644);
    assert_eq!(
        alloc_conn_id(&c1, MIN_CONN_ID, MAX_CONN_ID, |_| false),
        2_147_483_645,
        "mundo 1: maxId-1 es válido y se devuelve"
    );
    // 2. lado B: el candidato es `maxId` EXACTO ⇒ rebobina.
    let c2 = AtomicU32::new(2_147_483_645);
    assert_eq!(
        alloc_conn_id(&c2, MIN_CONN_ID, MAX_CONN_ID, |_| false),
        1,
        "mundo 2: candidato == maxId ⇒ rebobina a minId y devuelve 1"
    );
    // 3. muy por encima del tope.
    let c3 = AtomicU32::new(u32::MAX - 1);
    assert_eq!(
        alloc_conn_id(&c3, MIN_CONN_ID, MAX_CONN_ID, |_| false),
        1,
        "mundo 3: candidato == MaxUint32 ⇒ rebobina"
    );
    // 4. WRAPAROUND: sin `wrapping_add` esto PANICA en debug (overflow-checks on).
    let c4 = AtomicU32::new(u32::MAX);
    assert_eq!(
        alloc_conn_id(&c4, MIN_CONN_ID, MAX_CONN_ID, |_| false),
        0,
        "mundo 4: el Add envuelve a 0, que está EN RANGO ⇒ se devuelve 0 (celda C-09)"
    );
    assert_eq!(c4.load(Ordering::Relaxed), 0, "mundo 4: contador en 0");
}

/// `T-4` (`R-3`). «En uso» del port es la UNIÓN `conns ∪ binds` (el oráculo tiene UN mapa,
/// `mux.sinks`, que contiene dial, bind e hijas a la vez).
///
/// RB-SDK-09 (predicado COMPUESTO): la celda `5` satisface `conns` y NO `binds` (falsa la mitad
/// `conns` sin que la otra la enmascare); la celda `6` es su espejo; la celda `7` es el VECTOR DE
/// COLISIÓN (misma clave en AMBOS mapas), que se AÑADE y nunca sustituye a las ordinarias.
///
/// MUTACIONES ASESINAS (una por mitad): borrar la consulta a `binds` ⇒ muere la celda `6`; borrar la
/// consulta a `conns` ⇒ muere la celda `5`.
#[tokio::test]
async fn conn_id_in_use_is_the_union_of_conns_and_binds() {
    let (state, _task, _router) = rig();
    let (tx5, _rx5) = mpsc::channel(1);
    let (tx6, _rx6) = mpsc::channel(1);
    let (tx7a, _rx7a) = mpsc::channel(1);
    let (tx7b, _rx7b) = mpsc::channel(1);
    state.register_conn(5, tx5);
    state.register_bind(6, tx6);
    state.register_conn(7, tx7a);
    state.register_bind(7, tx7b);

    assert!(state.conn_id_in_use(5), "5 sólo en `conns` ⇒ en uso");
    assert!(state.conn_id_in_use(6), "6 sólo en `binds` ⇒ en uso");
    assert!(state.conn_id_in_use(7), "7 en AMBOS (colisión) ⇒ en uso");
    assert!(!state.conn_id_in_use(8), "8 en ninguno ⇒ libre");
}

/// `T-5` (`R-2` + `R-3`). El CABLEADO: que la función pura esté bien no prueba que `next_conn_id` la
/// use con el predicado real del canal.
///
/// MUTACIÓN ASESINA: cablear `in_use` a `|_| false` ⇒ devuelve `1`.
#[tokio::test]
async fn next_conn_id_skips_an_id_already_registered_as_a_bind() {
    let (state, _task, _router) = rig();
    let (tx, _rx) = mpsc::channel(1);
    state.register_bind(1, tx);
    assert_eq!(
        state.next_conn_id(),
        2,
        "el 1 está en `binds` ⇒ el generador lo SALTA"
    );
}
