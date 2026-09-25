//! Live edge auth + services. Ignored by default; see docs/edge-integration.md.
//! Run: `cargo test --test edge_integration -- --ignored`.

use noa_sdk::edge::client::{EdgeClient, ExtJwtConfig};
use noa_sdk::edge::model::SessionType;
use noa_sdk::enroll::{self, ott::EnrollOptions};
use std::path::PathBuf;

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("set {key} to a JWT path")))
}

#[tokio::test]
#[ignore = "requires a live OpenZiti controller (OrbStack); see docs/edge-integration.md"]
async fn enrol_then_authenticate_and_list_services() {
    // 1. Enrol a fresh identity with our crate.
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");

    // 2. Build the edge client and authenticate.
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // 3. List services (may be empty depending on policy).
    let services = client
        .list_services()
        .await
        .expect("list services succeeds");
    println!("services: {}", services.len());
    for s in &services {
        assert!(
            !s.id.is_empty() && !s.name.is_empty(),
            "service has id+name"
        );
    }
}

// Slice proactive-refresh: validate the GENUINELY-NEW `GET /current-api-session` wire (the
// `refresh()` method was dead code until this slice brought it to life — it had never run live).
// `noa-live-validation-rule`: only this new wire gets a live test; the TIMER LOGIC (scheduling /
// dedup / fallback) is wiremock + unit + injected clock, NOT live. We exercise the GET directly via
// the public `refresh()` (which now delegates to the same `do_refresh_get` the timer uses) and
// confirm the api-session is still alive afterwards (a subsequent control-plane call succeeds).
#[tokio::test]
#[ignore = "requires a live OpenZiti controller (OrbStack); validates the GET /current-api-session refresh wire"]
async fn enrol_then_refresh_extends_api_session() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // The new wire: GET /current-api-session. Must succeed against the real controller (and persist
    // the refreshed token + the extended expiry internally).
    client
        .refresh()
        .await
        .expect("GET /current-api-session (refresh) succeeds against the live controller");

    // The session is still alive after the refresh: a control-plane call works (proves the refreshed
    // token is valid and the api-session was extended, not invalidated).
    client
        .list_services()
        .await
        .expect("the api-session is alive after the refresh");

    // A second refresh works too (the sliding window keeps extending) — the proactive timer relies on
    // exactly this repeatability.
    client
        .refresh()
        .await
        .expect("a second refresh also succeeds (the window keeps extending)");
}

#[tokio::test]
#[ignore = "requires a live controller + online edge router + policies; see docs/edge-integration.md"]
async fn enrol_then_create_session() {
    // 1. Enrol a fresh identity and authenticate.
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // 2. Pick a dial-able service (avoids hardcoding the service id).
    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.permissions.iter().any(|p| p == "Dial"))
        .or_else(|| services.first())
        .expect("at least one service is visible (create a service + dial policy)");

    // 3. Create a dial session and assert the equivalence gate.
    let detail = client
        .create_session(&svc.id, SessionType::Dial)
        .await
        .expect("create_session succeeds");
    assert!(!detail.token.is_empty(), "session token present");
    assert!(!detail.edge_routers.is_empty(), "at least one edge router");
    let er = &detail.edge_routers[0];
    let tls = er.supported_protocols.get("tls").unwrap_or_else(|| {
        panic!(
            "edge router advertises a tls protocol: {:?}",
            er.supported_protocols
        )
    });
    // Equivalence gate for the one new behaviour of this slice: the SDK rewrites
    // `proto://host:port` -> `proto:host:port` (sanitizeSessionUrls). Confirm it on real data.
    assert!(
        !tls.contains("://"),
        "tls protocol URL is sanitized (no `://`): {tls}"
    );
    println!(
        "session {} on service {} via {} routers",
        detail.id,
        svc.name,
        detail.edge_routers.len()
    );
}

#[tokio::test]
#[ignore = "requires a live controller + online edge router + policies; see docs/edge-integration.md"]
async fn enrol_then_open_channel() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.permissions.iter().any(|p| p == "Dial"))
        .or_else(|| services.first())
        .expect("at least one service is visible");
    let detail = client
        .create_session(&svc.id, SessionType::Dial)
        .await
        .expect("create_session succeeds");

    // Equivalence gate: open the binary channel V2 to the router and complete the Hello/Result.
    let ch = client
        .open_channel(&detail)
        .await
        .expect("open_channel succeeds");
    println!(
        "channel open: router_id={:?} hello_version={:?}",
        ch.router_id(),
        ch.hello_version()
    );
    assert!(
        ch.hello_version().is_some(),
        "router advertised a hello version"
    );
    ch.close().await.expect("channel closes");
}

#[tokio::test]
#[ignore = "requires a live controller + online router + a HOSTED encryptionRequired=false service; see docs/edge-integration.md"]
async fn enrol_then_dial() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Select the PLAINTEXT (encryptionRequired=false), Dial-able fixture service BY NAME. Dialing the
    // encrypted testsvc without a public key would fail with EncryptionDataMissing, and picking "the
    // first" plaintext service is not deterministic: the controller lists services by id, which is
    // random, so it could pick one without a terminator (e.g. fwdsvc) and fail with "has no
    // terminators".
    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| {
            s.name == "testsvc-noenc"
                && !s.encryption_required
                && s.permissions.iter().any(|p| p == "Dial")
        })
        .expect(
            "the plaintext Dial fixture service testsvc-noenc exists (scripts/rig-fixtures.sh)",
        );
    println!("dialing plaintext service '{}'", svc.name);

    let detail = client
        .create_session(&svc.id, SessionType::Dial)
        .await
        .expect("create_session succeeds");
    let channel = client
        .open_channel(&detail)
        .await
        .expect("open_channel succeeds");

    // Connect -> StateConnected over the open channel.
    let mut conn = channel
        .dial(&detail, false, None, None)
        .await
        .expect("dial -> StateConnected");
    assert!(conn.conn_id() >= 1, "conn id allocated");
    assert!(conn.circuit_id().is_some(), "router reported a circuit id");

    // Equivalence gate: write bytes, read them echoed back (plaintext Data round-trip).
    conn.write(b"hello-slice4b\n").await.expect("write data");
    let echo = conn.read().await.expect("read echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-slice4b\n"[..]),
        "echo round-trips"
    );
    println!(
        "data round-trip OK: conn_id={} circuit={:?}",
        conn.conn_id(),
        conn.circuit_id()
    );
    conn.close().await.expect("conn closes");
    channel.close().await.expect("channel closes");
}

#[tokio::test]
#[ignore = "requires a live controller + online router + a HOSTED encryptionRequired=true service (testsvc); see docs/edge-integration.md"]
async fn enrol_then_dial_encrypted() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Select an ENCRYPTED (encryptionRequired=true), Dial-able service (testsvc).
    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.encryption_required && s.permissions.iter().any(|p| p == "Dial"))
        .expect("an encryptionRequired=true Dial service exists (testsvc, hosted)");
    println!("dialing encrypted service '{}'", svc.name);

    let detail = client
        .create_session(&svc.id, SessionType::Dial)
        .await
        .expect("create_session succeeds");
    let channel = client
        .open_channel(&detail)
        .await
        .expect("open_channel succeeds");

    // Crypto dial: kx + stream-header exchange happen inside dial().
    let mut conn = channel
        .dial(&detail, true, None, None)
        .await
        .expect("encrypted dial -> StateConnected");
    assert!(conn.circuit_id().is_some(), "router reported a circuit id");

    // Equivalence gate: the bytes on the wire are e2e ciphertext; the echo round-trips.
    conn.write(b"hello-slice5\n")
        .await
        .expect("write encrypted data");
    let echo = conn.read().await.expect("read decrypted echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-slice5\n"[..]),
        "encrypted echo round-trips"
    );
    println!(
        "encrypted round-trip OK: conn_id={} circuit={:?}",
        conn.conn_id(),
        conn.circuit_id()
    );
    conn.close().await.expect("conn closes");
    channel.close().await.expect("channel closes");
}

// Since slice 10c this is the live happy-path for the connect-side multi-router RACE:
// `connect()` opens the channel via `open_or_reuse_pooled_channel`, which reuses a pooled channel or
// races all `tls` routers and keeps the first. With a single `er1` the race picks it trivially (no
// regression). Real failover is not live-testable here (only one router in OrbStack) and is
// client-side logic over already-validated wire → it is covered by the duplex unit tests in
// `edge::channel`.
#[tokio::test]
#[ignore = "requires a live controller + online router + hosted testsvc/testsvc-noenc; see docs/edge-integration.md"]
async fn enrol_then_connect_both() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Plaintext service: connect by NAME and round-trip. crypto is OFF because the Service
    // says encryptionRequired=false — selected by connect(), not passed by hand.
    let mut noenc = client
        .connect("testsvc-noenc")
        .await
        .expect("connect(testsvc-noenc) succeeds");
    assert!(
        noenc.circuit_id().is_some(),
        "plaintext circuit established"
    );
    noenc.write(b"hello-slice6-plain\n").await.expect("write");
    assert_eq!(
        noenc.read().await.expect("read echo").as_deref(),
        Some(&b"hello-slice6-plain\n"[..]),
        "plaintext echo round-trips"
    );
    noenc.close().await.expect("close plaintext conn");

    // Encrypted service: same call shape; crypto is ON because the Service says
    // encryptionRequired=true. The bytes on the wire are e2e ciphertext.
    let mut enc = client
        .connect("testsvc")
        .await
        .expect("connect(testsvc) succeeds");
    assert!(enc.circuit_id().is_some(), "encrypted circuit established");
    enc.write(b"hello-slice6-enc\n").await.expect("write");
    assert_eq!(
        enc.read().await.expect("read decrypted echo").as_deref(),
        Some(&b"hello-slice6-enc\n"[..]),
        "encrypted echo round-trips"
    );
    enc.close().await.expect("close encrypted conn");
    println!("slice 6 connect() round-trip OK (plaintext + encrypted, flag from Service)");
}

/// Slice rx_loop-close-notify: validate the GENUINELY-NEW latency-probe wire (`CT_LATENCY`=3 ↔ the edge
/// router's `LatencyHandler` reply). NON-VACUOUS: our own probe fires after the 30s interval and, if NO
/// reply arrives within the 10s timeout, the read-idle check CLOSES the channel — so an idle channel
/// that is STILL usable past that window proves the router answered our `CT_LATENCY` probe (without a
/// response we would have torn it down ourselves). Per `noa-live-validation-rule`, only the new wire is
/// live; the death-detection LOGIC (timeout/read-idle/close-notify) is unit/duplex-covered. SLOW (~50s).
#[tokio::test]
#[ignore = "requires a live controller + router; SLOW (~50s idle); validates the latency-probe wire"]
async fn enrol_then_idle_channel_survives_latency_probe() {
    use std::time::Duration;
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Hold ONE connection (it owns a pooled channel + the latency-probe task) idle across the probe
    // window. (The pool keeps the channel; the conn holds an `Arc` clone, so the probe task lives.)
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect(testsvc-noenc) succeeds");
    conn.write(b"probe-pre\n").await.expect("write pre-idle");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"probe-pre\n"[..]),
        "pre-idle round-trip works"
    );

    // Scoring slice (A) — connectTime seed (NON-VACUOUS): the pooled channel was seeded with its real
    // handshake RTT, so its mean latency is finite and > 0. A dropped seed would leave it unsampled
    // (u64::MAX) and this would fail. < 60s is a sanity ceiling (a local handshake is milliseconds).
    let seed_mean = client
        .pooled_min_mean_latency_nanos()
        .expect("the connected channel is pooled");
    assert!(
        seed_mean > 0 && seed_mean < 60_000_000_000,
        "the pooled channel's mean latency is the finite, positive connectTime seed (got {seed_mean} ns)"
    );
    let samples_pre = client
        .pooled_max_latency_sample_count()
        .expect("the connected channel is pooled");
    assert_eq!(
        samples_pre, 1,
        "before any probe round, the only latency sample is the connectTime seed"
    );

    // Idle past one probe interval (30s) + the reply timeout (10s) + margin. The probe fires at ~30s; if
    // the router does NOT answer CT_LATENCY=3, our read-idle check closes the channel at ~40s.
    tokio::time::sleep(Duration::from_secs(45)).await;

    // The channel survived the probe window => the router answered the probe (else we'd have closed it).
    conn.write(b"probe-post\n")
        .await
        .expect("write post-idle: the channel survived the latency-probe window");
    assert_eq!(
        conn.read().await.expect("read echo after idle").as_deref(),
        Some(&b"probe-post\n"[..]),
        "an idle channel survives >=1 latency-probe interval => the router answered CT_LATENCY=3"
    );

    // Scoring slice (A) — probe RTT recording (NON-VACUOUS, the new surface on the primitive): after
    // ~45s the 30s probe fired and the router REPLIED, so the channel recorded a second latency sample
    // (the connectTime seed + >=1 probe round-trip). A dropped Alive-RTT record would leave it at 1.
    let samples_post = client
        .pooled_max_latency_sample_count()
        .expect("the connected channel is pooled");
    assert!(
        samples_post >= 2,
        "an answered probe records a round-trip latency sample (count={samples_post}, expected >=2)"
    );

    conn.close().await.expect("close conn");
    println!(
        "latency-probe wire OK: idle channel survived the 30s probe interval (router answered); \
         connectTime seed + probe RTT recorded (samples={samples_post})"
    );
}

// Pool slice (pool-first): a SECOND connect to the same router REUSES the pooled channel instead of
// opening a fresh TLS channel. NON-VACUOUS observables: `tls_channel_opens()` (real TLS handshakes)
// stays at 1 across FOUR connects, and `pooled_channel_count()` stays at 1. Also exercises the shared
// channel directly — two conns multiplexed live at once, and a sibling conn surviving the other's
// close (the 4b close-semantics re-architecture) — plus an encrypted connect riding the reused
// channel. Without the pool each connect would open its own channel (tls_channel_opens would be 4).
#[tokio::test]
#[ignore = "requires a live controller + online router + hosted testsvc/testsvc-noenc; pool slice reuse proof"]
async fn enrol_then_connect_reuses_pooled_channel() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "no router channel opened before the first connect"
    );

    // Connect #1: opens exactly ONE router channel, pooled.
    let mut c1 = client.connect("testsvc-noenc").await.expect("connect #1");
    assert_eq!(
        client.tls_channel_opens(),
        1,
        "the first connect opens exactly one router channel"
    );
    assert_eq!(client.pooled_channel_count(), 1, "the channel is pooled");
    c1.write(b"pool-reuse-1\n").await.expect("write #1");
    assert_eq!(
        c1.read().await.expect("read #1").as_deref(),
        Some(&b"pool-reuse-1\n"[..]),
        "round-trip #1"
    );

    // Connect #2 to the SAME service over the SAME router → REUSE: no second TLS handshake.
    let mut c2 = client.connect("testsvc-noenc").await.expect("connect #2");
    assert_eq!(
        client.tls_channel_opens(),
        1,
        "the SECOND connect REUSES the pooled channel — NO new TLS handshake (the pool's point)"
    );
    assert_eq!(
        client.pooled_channel_count(),
        1,
        "still a single pooled channel"
    );
    assert_ne!(
        c1.conn_id(),
        c2.conn_id(),
        "two distinct conns multiplexed over the one shared channel"
    );
    c2.write(b"pool-reuse-2\n").await.expect("write #2");
    assert_eq!(
        c2.read().await.expect("read #2").as_deref(),
        Some(&b"pool-reuse-2\n"[..]),
        "round-trip #2 over the reused channel"
    );

    // Conn #1 still works AFTER #2 reused its channel (genuine simultaneous multiplexing).
    c1.write(b"pool-reuse-1b\n").await.expect("write #1b");
    assert_eq!(
        c1.read().await.expect("read #1b").as_deref(),
        Some(&b"pool-reuse-1b\n"[..]),
        "conn #1 still works after conn #2 reused the shared channel"
    );

    // Closing conn #1 must NOT kill the shared channel: conn #2 keeps working (close-semantics flip).
    c1.close().await.expect("close #1");
    c2.write(b"pool-reuse-2b\n")
        .await
        .expect("write #2b after closing #1");
    assert_eq!(
        c2.read().await.expect("read #2b").as_deref(),
        Some(&b"pool-reuse-2b\n"[..]),
        "conn #2 survives conn #1's close — the pool keeps the shared channel alive"
    );
    assert_eq!(
        client.tls_channel_opens(),
        1,
        "no extra handshake the whole time"
    );
    c2.close().await.expect("close #2");

    // An ENCRYPTED connect over a DIFFERENT service but the SAME router also reuses the channel — the
    // crypto partition rides the shared channel.
    let mut enc = client
        .connect("testsvc")
        .await
        .expect("connect(testsvc) encrypted");
    assert_eq!(
        client.tls_channel_opens(),
        1,
        "the encrypted connect over the same router still reuses — no new handshake"
    );
    enc.write(b"pool-reuse-enc\n").await.expect("write enc");
    assert_eq!(
        enc.read().await.expect("read enc").as_deref(),
        Some(&b"pool-reuse-enc\n"[..]),
        "encrypted round-trip over the reused channel"
    );
    enc.close().await.expect("close enc");

    println!(
        "pool slice OK: 4 connects (3 plaintext + 1 encrypted) over ONE reused router channel \
         (tls_channel_opens=1, pooled_channel_count=1)"
    );
}

#[tokio::test]
#[ignore = "requires a live controller + online router + a Bind-able service (bindsvc); pre-flight: scripts/rig-fixtures.sh; see docs/edge-integration.md"]
async fn enrol_then_bind() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Register as a host of the dedicated bind-only service. Success = StateConnected reply
    // (a terminator is registered on the controller; verify with `ziti edge list terminators`).
    let binding = client
        .bind("bindsvc")
        .await
        .expect("bind(bindsvc) succeeds");
    assert!(binding.conn_id() >= 1, "bind conn id allocated");
    println!("bound 'bindsvc': conn_id={}", binding.conn_id());
    binding.close().await.expect("unbind + close");
}

#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc (Bind+Dial policies) + 2 JWTs; pre-flight: scripts/rig-fixtures.sh; see docs/edge-integration.md"]
async fn bind_then_serve_roundtrip() {
    use std::time::Duration;

    // Host identity: enrol, auth, bind(bindsvc), then accept+echo in the background.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let mut binding = host.bind("bindsvc").await.expect("bind(bindsvc) succeeds");
    println!("host bound 'bindsvc': conn_id={}", binding.conn_id());

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let (sid_tx, sid_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    let host_task = tokio::spawn(async move {
        // Accept ONE inbound dial and echo ONE message back through our host.
        let mut conn = binding.accept().await.expect("host accepts a dial");
        println!("host accepted child conn_id={}", conn.conn_id());
        let _ = sid_tx.send(conn.source_identity().map(ToOwned::to_owned));
        let data = conn
            .read()
            .await
            .expect("host reads from dialer")
            .expect("dialer sent data");
        conn.write(&data).await.expect("host echoes");
        let _ = done_rx.await; // keep the binding (rx-loop) alive until the dialer is done
        let _ = conn.close().await;
        let _ = binding.close().await;
    });

    // Dialer identity: enrol, auth, connect(bindsvc) -> routed to OUR host -> round-trip.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");
    let mut dconn = dialer
        .connect("bindsvc")
        .await
        .expect("dialer connect(bindsvc)");
    dconn.write(b"hello-7b1\n").await.expect("dialer writes");
    let echo = tokio::time::timeout(Duration::from_secs(20), dconn.read())
        .await
        .expect("dialer read did not time out")
        .expect("dialer reads echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-7b1\n"[..]),
        "payload echoed back THROUGH our host"
    );
    println!("7b-1 serve round-trip OK: data echoed by our host");
    // Slice 8 equivalence gate: the host saw EXACTLY the dialer's own identity name
    // (host wire-read CallerId == dialer's api-session identity name).
    let observed = tokio::time::timeout(Duration::from_secs(20), sid_rx)
        .await
        .expect("source identity reported in time")
        .expect("host task alive");
    assert!(
        dialer.identity_name().is_some(),
        "dialer knows its identity name"
    );
    assert_eq!(
        observed.as_deref(),
        dialer.identity_name(),
        "host source_identity == dialer's own identity name (CallerId propagated)"
    );
    println!("slice 8 CallerId OK (plaintext): host saw dialer '{observed:?}'");
    dconn.close().await.ok();

    let _ = done_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), host_task)
        .await
        .expect("host task finishes in time")
        .expect("host task ok");
}

/// Slice rx_loop-close-notify (review BR-1): the latency probe is spawned on EVERY channel, including a
/// long-lived idle BIND/host channel — the MOST production-likely 30s-idle case (a `ServiceBinding` sits
/// idle waiting for inbound dials). This asserts the BIND channel survives the probe window: the host
/// binds, then idles past the 30s interval + 10s timeout, and only THEN does a dialer connect and
/// round-trip. If the router did not reflect `CT_LATENCY=3` on the bind channel, our read-idle check
/// would have closed it at ~40s and the accept/echo would fail. SLOW (~50s).
#[tokio::test]
#[ignore = "requires a live controller + router + bindsvc + 2 JWTs; SLOW (~50s); validates bind-channel idle-survival; pre-flight: scripts/rig-fixtures.sh"]
async fn bind_then_idle_then_serve_roundtrip() {
    use std::time::Duration;

    // Host: enrol, auth, bind(bindsvc), then block on accept (idling the bind channel) and echo.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let mut binding = host.bind("bindsvc").await.expect("bind(bindsvc) succeeds");
    println!(
        "host bound 'bindsvc' (will idle past the probe window): conn_id={}",
        binding.conn_id()
    );

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let host_task = tokio::spawn(async move {
        // accept() idles the bind channel (its rx-loop + probe run) until the post-idle dial arrives.
        let mut conn = binding
            .accept()
            .await
            .expect("host accepts a dial AFTER the bind channel idled past the probe window");
        let data = conn
            .read()
            .await
            .expect("host reads from dialer")
            .expect("dialer sent data");
        conn.write(&data).await.expect("host echoes");
        let _ = done_rx.await;
        let _ = conn.close().await;
        let _ = binding.close().await;
    });

    // Idle the bind channel past one full probe window (30s interval + 10s reply timeout + margin). The
    // probe fires on the bind channel at ~30s; if the router does not reflect it, the channel closes at
    // ~40s and the accept above never sees the dial.
    tokio::time::sleep(Duration::from_secs(45)).await;

    // Dialer connects AFTER the idle → routed to OUR (still-alive) host bind channel → round-trip.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");
    let mut dconn = dialer
        .connect("bindsvc")
        .await
        .expect("dialer connect(bindsvc) AFTER host idled the bind channel");
    dconn
        .write(b"hello-bind-idle\n")
        .await
        .expect("dialer writes");
    let echo = tokio::time::timeout(Duration::from_secs(20), dconn.read())
        .await
        .expect("dialer read did not time out")
        .expect("dialer reads echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-bind-idle\n"[..]),
        "the BIND channel survived the latency-probe window => the router reflected CT_LATENCY=3 on it"
    );
    println!(
        "bind-channel idle-survival OK: bind channel survived the 30s probe interval, then served"
    );
    dconn.close().await.ok();
    let _ = done_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), host_task)
        .await
        .expect("host task finishes in time")
        .expect("host task ok");
}

#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc-enc (encryptionRequired=true, Bind+Dial policies) + 2 JWTs; pre-flight: scripts/rig-fixtures.sh; see docs/edge-integration.md"]
async fn bind_then_serve_encrypted_roundtrip() {
    use std::time::Duration;

    // Host identity: enrol, auth, bind(bindsvc-enc), accept+echo in the background.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let mut binding = host
        .bind("bindsvc-enc")
        .await
        .expect("bind(bindsvc-enc) succeeds");
    println!(
        "host bound 'bindsvc-enc' (encrypted): conn_id={}",
        binding.conn_id()
    );

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let (sid_tx, sid_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    let host_task = tokio::spawn(async move {
        let mut conn = binding
            .accept()
            .await
            .expect("host accepts an encrypted dial");
        println!("host accepted encrypted child conn_id={}", conn.conn_id());
        let _ = sid_tx.send(conn.source_identity().map(ToOwned::to_owned));
        let data = conn
            .read()
            .await
            .expect("host reads (decrypted)")
            .expect("dialer sent data");
        conn.write(&data).await.expect("host echoes (encrypted)");
        let _ = done_rx.await; // keep the binding (rx-loop) alive until the dialer is done
        let _ = conn.close().await;
        let _ = binding.close().await;
    });

    // Dialer identity: enrol, auth, connect(bindsvc-enc) -> routed to OUR host -> e2e-encrypted.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");
    let mut dconn = dialer
        .connect("bindsvc-enc")
        .await
        .expect("dialer connect(bindsvc-enc)");
    dconn
        .write(b"hello-7b2-enc\n")
        .await
        .expect("dialer writes (encrypted)");
    let echo = tokio::time::timeout(Duration::from_secs(20), dconn.read())
        .await
        .expect("dialer read did not time out")
        .expect("dialer reads echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-7b2-enc\n"[..]),
        "encrypted payload echoed back THROUGH our host"
    );
    println!("7b-2 ENCRYPTED serve round-trip OK: data e2e-encrypted and echoed by our host");
    // Slice 8 equivalence gate: the host saw EXACTLY the dialer's own identity name
    // (host wire-read CallerId == dialer's api-session identity name).
    let observed = tokio::time::timeout(Duration::from_secs(20), sid_rx)
        .await
        .expect("source identity reported in time")
        .expect("host task alive");
    assert!(
        dialer.identity_name().is_some(),
        "dialer knows its identity name"
    );
    assert_eq!(
        observed.as_deref(),
        dialer.identity_name(),
        "host source_identity == dialer's own identity name (CallerId propagated)"
    );
    println!("slice 8 CallerId OK (encrypted): host saw dialer '{observed:?}'");
    dconn.close().await.ok();

    let _ = done_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), host_task)
        .await
        .expect("host task finishes in time")
        .expect("host task ok");
}

#[tokio::test]
#[ignore = "requires a live controller + online router + hosted testsvc-noenc; see docs/edge-integration.md"]
async fn enrol_then_connect_twice_reuses_dial_session() {
    // Slice 9: two connect() calls to the same service. The first is a cache miss (creates the
    // Dial session); the second is a cache hit (reuses it — no new create-session POST). The
    // create-once proof is the wiremock unit test (it counts POSTs); this live test confirms the
    // happy path + the cached path both dial and round-trip with no regression.
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    let mut first = client
        .connect("testsvc-noenc")
        .await
        .expect("first connect");
    first.write(b"slice9-first\n").await.expect("write 1");
    assert_eq!(
        first.read().await.expect("read 1").as_deref(),
        Some(&b"slice9-first\n"[..]),
        "first connect round-trips"
    );
    first.close().await.expect("close 1");

    let mut second = client
        .connect("testsvc-noenc")
        .await
        .expect("second connect (cached Dial session)");
    second.write(b"slice9-second\n").await.expect("write 2");
    assert_eq!(
        second.read().await.expect("read 2").as_deref(),
        Some(&b"slice9-second\n"[..]),
        "second connect (cached session) round-trips"
    );
    second.close().await.expect("close 2");
    println!("slice 9 connect() twice OK (2nd reuses the cached Dial session)");
}

// Slice E1 (enrolment arc): RSA-4096 as the client key algorithm. NEW wire — the controller signs
// an RSA CSR for the first time — so this earns a live test (live-validation rule: new wire needs a live test). It also
// exercises the *subsequent* mTLS auth + dial with an RSA-4096 client cert. The end-to-end round-trip
// proves the RSA identity authenticates and dials.
#[tokio::test]
#[ignore = "requires a live controller + online router + hosted testsvc-noenc; see docs/edge-integration.md"]
async fn enrol_rsa_then_connect() {
    use noa_sdk::enroll::csr::KeyAlg;

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let opts = EnrollOptions {
        key_alg: KeyAlg::Rsa4096,
        ..Default::default()
    };
    let cfg = enroll::ott::enroll(jwt.trim(), opts)
        .await
        .expect("RSA-4096 enrolment succeeds");
    // The signed client cert + its RSA key must drive mTLS auth and a dial.
    let mut client = EdgeClient::from_identity(&cfg).expect("RSA mTLS client builds");
    client
        .authenticate()
        .await
        .expect("authenticate with RSA-4096 client cert succeeds");

    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect(testsvc-noenc) with an RSA identity succeeds");
    assert!(
        conn.circuit_id().is_some(),
        "RSA identity circuit established"
    );
    conn.write(b"hello-e1-rsa\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-e1-rsa\n"[..]),
        "RSA identity echo round-trips"
    );
    conn.close().await.expect("close RSA conn");
    println!("slice E1 RSA-4096 enrol + mTLS auth + connect() round-trip OK");
}

// Slice E2 (enrolment arc): `ottca` — enrol with a PRE-EXISTING, CA-issued identity (cert+key)
// authenticated over mTLS, instead of generating a key/CSR. NEW wire (the controller registers an
// identity via an mTLS empty-body POST) → live test (live-validation rule: new wire needs a live test). Setup (spike
// recipe, ~5 commands; see docs/superpowers/specs/2026-06-19-enroll-ottca-design.md §2): create a
// CA, register it `--ottca --auth`, verify it, `ziti edge create enrollment ottca <identityId>
// <caId> -o <jwt>`, and `ziti pki create client` for the cert+key. Env:
//   ZITI_EDGE_JWT_OTTCA  -> the ottca enrolment JWT
//   ZITI_EDGE_OTTCA_CERT -> the CA-issued client cert PEM (leaf [+ CA chain])
//   ZITI_EDGE_OTTCA_KEY  -> the client private key PEM
#[tokio::test]
#[ignore = "requires a live controller + a verified ottca CA + a CA-issued client cert; see docs/superpowers/specs/2026-06-19-enroll-ottca-design.md"]
async fn enrol_ottca() {
    use noa_sdk::enroll::ott::ProvidedIdentity;

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_OTTCA")).unwrap();
    let cert_pem = std::fs::read_to_string(env_path("ZITI_EDGE_OTTCA_CERT")).unwrap();
    let key_pem = std::fs::read_to_string(env_path("ZITI_EDGE_OTTCA_KEY")).unwrap();

    let opts = EnrollOptions {
        client_identity: Some(ProvidedIdentity { cert_pem, key_pem }),
        ..Default::default()
    };
    // ottca: the controller registers the identity via mTLS with the CA-issued cert; no key/CSR,
    // no new cert. The resulting Config reuses the provided cert+key.
    let cfg = enroll::ott::enroll(jwt.trim(), opts)
        .await
        .expect("ottca enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("ottca mTLS client builds");
    client
        .authenticate()
        .await
        .expect("authenticate with the CA-issued client cert succeeds");

    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect(testsvc-noenc) with the ottca identity succeeds");
    assert!(
        conn.circuit_id().is_some(),
        "ottca identity circuit established"
    );
    conn.write(b"hello-e2-ottca\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-e2-ottca\n"[..]),
        "ottca identity echo round-trips"
    );
    conn.close().await.expect("close ottca conn");
    println!("slice E2 ottca enrol + mTLS auth + connect() round-trip OK");
}

// Slice E4a (enrolment arc): `updb` enrolment (username/password). NEW wire (the controller sets the
// password + confirms the username) → live test (live-validation rule: new wire needs a live test). Setup:
//   ziti edge create identity e4updb2 --updb e4user2 -o /tmp/e4updb2.jwt
// Env: ZITI_EDGE_JWT_UPDB (jwt path), ZITI_EDGE_UPDB_USER (default e4user2), ZITI_EDGE_UPDB_PASS.
// E4a validates the enrolment POST returns the confirmed username; the auth+connect (E4b) is a follow-up.
#[tokio::test]
#[ignore = "requires a live controller + a updb identity (ziti edge create identity --updb); see docs/superpowers/specs/2026-06-19-enroll-updb-design.md"]
async fn enrol_updb() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_UPDB")).unwrap();
    let username = std::env::var("ZITI_EDGE_UPDB_USER").unwrap_or_else(|_| "e4user2".into());
    let password = std::env::var("ZITI_EDGE_UPDB_PASS").unwrap_or_else(|_| "e4password123".into());

    let cfg = enroll::updb::enroll_updb(jwt.trim(), &username, &password, EnrollOptions::default())
        .await
        .expect("updb enrolment succeeds");
    assert_eq!(
        cfg.username, username,
        "controller confirms the supplied username"
    );
    assert_eq!(
        cfg.password, password,
        "UpdbConfig carries the set password"
    );
    assert!(
        cfg.ca.contains("BEGIN CERTIFICATE"),
        "UpdbConfig carries the controller CA bundle"
    );
    println!("slice E4a updb enrol OK: username={}", cfg.username);
}

// Slice S1 (session-certs arc): acquire an api-session client certificate. NEW wire (the controller
// mints an ephemeral mTLS cert from a posted CSR) → live test (live-validation rule: new wire needs a live test). S1 is
// auth-method-independent, so a cert (ott) identity is the right live fixture. Setup:
//   ziti edge create identity sc1 -o /tmp/sc1.jwt ; export ZITI_EDGE_JWT=/tmp/sc1.jwt
// Equivalence gate: the minted leaf parses, is EC P-256 (oracle client.go:334), and carries the
// TLS-client-auth EKU (so it works as a router mTLS cert in S2). Delete the identity after the run.
#[tokio::test]
#[ignore = "requires a live controller (OrbStack); see docs/superpowers/specs/2026-06-19-session-certs-design.md"]
async fn enrol_then_acquire_session_cert() {
    use x509_cert::Certificate;
    use x509_cert::der::DecodePem;
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::ext::pkix::ExtendedKeyUsage;

    // OIDs of the equivalence gate.
    const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const OID_SECP256R1: &str = "1.2.840.10045.3.1.7"; // P-256 named curve
    const OID_KP_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2"; // TLS Web Client Authentication

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // Mint the session cert (the new wire).
    let sc = client
        .acquire_session_cert()
        .await
        .expect("acquire_api_session_cert -> 201 SessionCert");
    assert!(!sc.id.is_empty(), "controller returned a cert id");
    assert!(
        sc.key_pem.contains("BEGIN PRIVATE KEY"),
        "ephemeral PKCS#8 key present"
    );

    // The leaf parses as a single X.509 cert.
    let leaf = Certificate::from_pem(sc.leaf_pem.as_bytes()).expect("leaf parses as X.509");

    // EC P-256: SPKI algorithm = ecPublicKey, named curve = secp256r1.
    let spki = &leaf.tbs_certificate.subject_public_key_info;
    assert_eq!(
        spki.algorithm.oid.to_string(),
        OID_EC_PUBLIC_KEY,
        "leaf is an EC key"
    );
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .clone()
        .expect("EC named-curve parameters")
        .decode_as()
        .expect("curve OID");
    assert_eq!(curve.to_string(), OID_SECP256R1, "leaf is EC P-256");

    // EKU carries TLS client auth (so it can drive the router mTLS in S2).
    let (_critical, eku) = leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .expect("decode EKU extension")
        .expect("leaf has an ExtendedKeyUsage extension");
    assert!(
        eku.0
            .iter()
            .any(|oid| oid.to_string() == OID_KP_CLIENT_AUTH),
        "leaf EKU includes TLS client auth: {:?}",
        eku.0
    );
    println!(
        "slice S1 OK: minted EC P-256 client-auth session cert id={} (leaf {} B, chain {} B)",
        sc.id,
        sc.leaf_pem.len(),
        sc.chain_pem.len()
    );
}

// Slice S2 (session-certs arc): `EdgeClient::from_updb` — updb CONNECT end-to-end. NEW wire
// (`POST /authenticate?method=password` for a NON-admin updb identity, then token-only control plane
// over a NON-mTLS client, then a session-cert minted to drive the router mTLS) → live test
// (live-validation rule: new wire needs a live test). This is the REAL gate of the whole arc: it proves password-auth +
// token-only list_services/create_session + leaf-only router mTLS all work together. Setup (give the
// updb identity its OWN fresh JWT):
//   ziti edge login localhost:1280 -u admin -p admin -y
//   ziti edge create identity s2updb --updb -o /tmp/s2updb.jwt
//   export ZITI_EDGE_JWT_UPDB_S2=/tmp/s2updb.jwt ZITI_EDGE_UPDB_S2_PASS=s2password123
// (and delete the identity after: `ziti edge delete identity s2updb`).
// Equivalence gate: connect("testsvc-noenc") → plaintext echo round-trips through the router.
#[tokio::test]
#[ignore = "requires a live controller + router + a fresh updb identity (--updb) + testsvc-noenc; see docs/superpowers/specs/2026-06-19-session-certs-design.md §7"]
async fn enrol_updb_then_connect() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_UPDB_S2")).unwrap();
    let username = std::env::var("ZITI_EDGE_UPDB_S2_USER").unwrap_or_default();
    let password =
        std::env::var("ZITI_EDGE_UPDB_S2_PASS").unwrap_or_else(|_| "s2password123".into());

    // 1. Enrol updb (sets the password, no cert) → UpdbConfig.
    let cfg = enroll::updb::enroll_updb(jwt.trim(), &username, &password, EnrollOptions::default())
        .await
        .expect("updb enrolment sets the password");
    assert_eq!(
        cfg.password, password,
        "UpdbConfig carries the set password"
    );

    // 2. from_updb: password-auth → session-cert → READY client (synthetic Config wired to channel).
    let client = EdgeClient::from_updb(&cfg)
        .await
        .expect("from_updb: password-auth + session-cert + ready client");
    assert!(
        client.identity_name().is_some(),
        "from_updb captured the api-session identity name"
    );

    // 3. connect("testsvc-noenc") over the session-cert mTLS to the router → plaintext round-trip.
    //    This exercises the token-only control plane (list_services + create_session over the
    //    non-mTLS http client) AND the leaf-only router mTLS handshake — the arc's whole point.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("updb connect(testsvc-noenc) succeeds");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-s2-updb\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-s2-updb\n"[..]),
        "updb plaintext echo round-trips through the router"
    );
    conn.close().await.expect("close updb conn");
    println!(
        "slice S2 OK: updb from_updb + connect(testsvc-noenc) round-trip (identity={:?})",
        client.identity_name()
    );
}

// ───────────────────────────── OIDC-1 (OIDC auth + Bearer control-plane) ─────────────────────────────
//
// NEW wire (the whole OIDC PKCE handshake + Bearer control-plane + the ~900B JWT in the channel Hello
// header 1002) → live (live-validation rule: new wire needs a live test). The cert-OIDC api-session is BOUND to the cert
// fingerprint (z_cfs), so the control-plane mTLS client (from_identity's `http`) MUST carry the cert —
// proven live in the cert-probe. Setup: a fresh OTT JWT in ZITI_EDGE_JWT_OIDC (single-use).
//   ziti edge create identity oidc1 -o /tmp/oidc1.jwt
//   export ZITI_EDGE_JWT_OIDC=/tmp/oidc1.jwt

#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + online router + testsvc/testsvc-noenc; OIDC-1"]
async fn enrol_then_connect_oidc() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_OIDC")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    // OIDC cert grant: from_identity (mTLS http, carries the cert for the z_cfs-bound control plane)
    // + authenticate_oidc (the PKCE cert flow → Bearer api-session). Confirms the ~900B JWT rides the
    // channel Hello header 1002 (the top residual live risk).
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client
        .authenticate_oidc()
        .await
        .expect("OIDC cert authenticate succeeds (Bearer + cert-bound control plane)");
    assert!(
        client.identity_name().is_some(),
        "OIDC auth captured the id_token identity name"
    );

    // Plaintext: connect by NAME (control plane over the Bearer + cert) → round-trip echo.
    let mut noenc = client
        .connect("testsvc-noenc")
        .await
        .expect("OIDC connect(testsvc-noenc) succeeds");
    assert!(
        noenc.circuit_id().is_some(),
        "plaintext circuit established"
    );
    noenc.write(b"hello-oidc-plain\n").await.expect("write");
    assert_eq!(
        noenc.read().await.expect("read echo").as_deref(),
        Some(&b"hello-oidc-plain\n"[..]),
        "OIDC plaintext echo round-trips"
    );
    noenc.close().await.expect("close plaintext conn");

    // Encrypted: same call shape, e2e crypto on (the channel Hello still carries the Bearer JWT).
    let mut enc = client
        .connect("testsvc")
        .await
        .expect("OIDC connect(testsvc) succeeds");
    assert!(enc.circuit_id().is_some(), "encrypted circuit established");
    enc.write(b"hello-oidc-enc\n").await.expect("write");
    assert_eq!(
        enc.read().await.expect("read decrypted echo").as_deref(),
        Some(&b"hello-oidc-enc\n"[..]),
        "OIDC encrypted echo round-trips"
    );
    enc.close().await.expect("close encrypted conn");
    println!(
        "OIDC-1 cert connect() round-trip OK (plaintext + encrypted, Bearer+cert control plane, identity={:?})",
        client.identity_name()
    );
}

// updb-OIDC: password grant. The api-session is a Bearer (z_cfs:null → control plane is token-only),
// and the session-cert mint authenticates with the BEARER (probed live: 201). Setup: a fresh updb JWT
// in ZITI_EDGE_JWT_UPDB_OIDC + the password in ZITI_EDGE_UPDB_OIDC_PASS.
//   ziti edge create identity oidcupdb --updb oidcupdb -o /tmp/oidcupdb.jwt
//   export ZITI_EDGE_JWT_UPDB_OIDC=/tmp/oidcupdb.jwt ZITI_EDGE_UPDB_OIDC_PASS=oidcpassword123
#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + online router + testsvc-noenc; OIDC-1 updb"]
async fn enrol_updb_then_connect_oidc() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_UPDB_OIDC")).unwrap();
    let username = std::env::var("ZITI_EDGE_UPDB_OIDC_USER").unwrap_or_default();
    let password =
        std::env::var("ZITI_EDGE_UPDB_OIDC_PASS").unwrap_or_else(|_| "oidcpassword123".into());

    // 1. Enrol updb (sets the password, no cert) → UpdbConfig.
    let cfg = enroll::updb::enroll_updb(jwt.trim(), &username, &password, EnrollOptions::default())
        .await
        .expect("updb enrolment sets the password");

    // 2. from_updb_oidc: OIDC password grant → Bearer → Bearer-authed session-cert mint → READY.
    let client = EdgeClient::from_updb_oidc(&cfg)
        .await
        .expect("from_updb_oidc: OIDC password-auth + Bearer session-cert mint + ready client");
    assert!(
        client.identity_name().is_some(),
        "from_updb_oidc captured the id_token identity name"
    );

    // 3. connect over the Bearer control plane + session-cert mTLS → plaintext round-trip.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("updb-OIDC connect(testsvc-noenc) succeeds");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-oidc-updb\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-oidc-updb\n"[..]),
        "updb-OIDC plaintext echo round-trips through the router"
    );
    conn.close().await.expect("close updb-OIDC conn");
    println!(
        "OIDC-1 updb from_updb_oidc + connect(testsvc-noenc) round-trip OK (identity={:?})",
        client.identity_name()
    );
}

// ext-jwt slice 1: `EdgeClient::from_ext_jwt` END-TO-END via OIDC. An external IdP JWT (bound to a
// pre-existing identity by externalId == JWT `sub`) is presented as `Authorization: Bearer <jwt>` on
// the OIDC `/oidc/login/ext-jwt` POST → Bearer api-session → Bearer-authed session-cert mint →
// connect round-trip. NEW WIRE (the ext-jwt login leg) → live obligatory (live-validation rule: new wire needs a live test).
//
// Setup (reusable spike fixtures — see HANDOFF "Infra viva en OrbStack"):
//   ZITI_EXT_JWT=$(bash ~/.noa-extjwt-fixtures/setup_and_mint.sh | tail -1 | cut -d= -f2-)
//   export ZITI_EXT_JWT   # the JWT VALUE (the fixture prints `ZITI_EXT_JWT=<jwt>`; ext-jwt is short-lived)
//   # Controller CA bundle (one-off, reusable; the fixtures do not emit it):
//   curl -sk https://localhost:1280/edge/client/v1/.well-known/est/cacerts \
//     | openssl base64 -d | openssl pkcs7 -inform DER -print_certs -out /tmp/ctrl-ca.pem
//   export ZITI_CTRL_CA=/tmp/ctrl-ca.pem
//   # (optional) ZITI_CTRL_URL=https://localhost:1280/edge/client/v1
// The identity `noaExtJwtSpikeId` has dial access to testsvc-noenc via the `dial-all` (#all/#all)
// service-policy (verified). ext-jwt consumes no OTT → the identity is reusable; only the JWT is fresh.
#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + router + testsvc-noenc + the ext-jwt fixtures; ext-jwt slice 1"]
async fn enrol_ext_jwt_then_connect() {
    // The JWT is read as a VALUE (env var content), not a path — it is short-lived and minted per run.
    let jwt =
        std::env::var("ZITI_EXT_JWT").expect("set ZITI_EXT_JWT to a fresh external JWT value");
    let ca = std::fs::read_to_string(env_path("ZITI_CTRL_CA"))
        .expect("read the controller CA bundle (ZITI_CTRL_CA path)");
    let zt_api = std::env::var("ZITI_CTRL_URL")
        .unwrap_or_else(|_| "https://localhost:1280/edge/client/v1".into());

    let cfg = ExtJwtConfig { zt_api, ca };

    // from_ext_jwt: OIDC ext-jwt grant → Bearer api-session → Bearer-authed session-cert mint → READY.
    let client = EdgeClient::from_ext_jwt(jwt.trim(), &cfg)
        .await
        .expect("from_ext_jwt: OIDC ext-jwt auth + Bearer session-cert mint + ready client");
    assert!(
        client.identity_name().is_some(),
        "from_ext_jwt captured the id_token identity name"
    );

    // connect over the Bearer control plane + session-cert mTLS → plaintext round-trip echo.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("ext-jwt connect(testsvc-noenc) succeeds");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-ext-jwt\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-ext-jwt\n"[..]),
        "ext-jwt plaintext echo round-trips through the router"
    );
    conn.close().await.expect("close ext-jwt conn");
    println!(
        "ext-jwt slice 1: from_ext_jwt + connect(testsvc-noenc) round-trip OK (identity={:?})",
        client.identity_name()
    );
}

// ───────────────────────────── MFA-1 (TOTP secondary auth via OIDC) ─────────────────────────────
//
// NEW wire (the OIDC `/oidc/login/totp` secondary-auth leg: 200+`totp-required` → submit `{code,id}`
// → 302) → live OBLIGATORY (live-validation rule: new wire needs a live test). The `mfaspike` identity (a CERT identity,
// ott-enrolled, MFA enrolled+verified) authenticates via the OIDC CERT grant with a TOTP provider that
// computes a FRESH RFC 6238 code from the fixture's base32 secret → secondary auth completes → connect
// `testsvc-noenc` → echo round-trip. The provider is the load-bearing seam: the SDK never computes the
// code, the test does (HMAC-SHA1, dev-only hmac/sha1).
//
// Reusable fixture (see HANDOFF "Infra viva en OrbStack" + /tmp/mfaspike-FIXTURE-RECIPE.md):
//   identity `mfaspike` (cert valid to 2027-06-20, MFA enrolled+verified); files
//   /tmp/mfaspike.{json,secret}; TOTP base32 secret `3HRE4SOYCP3NJEO5`. `mfaspike` has dial access
//   to testsvc-noenc via the `dial-all` (#all/#all) service-policy (verified pre-flight). The identity
//   is REUSABLE (the cert/MFA do not consume an OTT). No env vars: the fixture paths are fixed.
//   Override with MFASPIKE_IDENTITY (the identity JSON path) + MFASPIKE_SECRET (the base32 secret).
//
// NOTE: a single real-time TOTP is computed at login, so there is a ~sub-second flake window if the
// run crosses a 30s step boundary between mint and submit. A retry resolves it; a failure here is a
// timing artifact, NOT a wire break.

/// Compute the current RFC 6238 TOTP code (HMAC-SHA1, 30s step, 6 digits) from a base32 secret.
/// DEV-ONLY: this is the CALLER's job (the SDK never computes a code). Mirrors the math validated in
/// the spike against the RFC vectors (T=59→94287082, T=1111111109→07081804) before going live.
fn compute_totp(secret_b32: &str) -> String {
    use hmac::{Mac, SimpleHmac};
    use sha1::Sha1;

    let key = data_encoding::BASE32
        .decode(secret_b32.trim().as_bytes())
        .expect("the fixture secret is valid base32");
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
        / 30;
    let mut mac = SimpleHmac::<Sha1>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // RFC 4226 dynamic truncation.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(digest[offset]) & 0x7f) << 24
        | (u32::from(digest[offset + 1]) & 0xff) << 16
        | (u32::from(digest[offset + 2]) & 0xff) << 8
        | (u32::from(digest[offset + 3]) & 0xff);
    format!("{:06}", bin % 1_000_000)
}

#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + router + testsvc-noenc + the mfaspike MFA fixture; MFA-1"]
async fn mfaspike_oidc_totp_then_connect() {
    use noa_sdk::enroll::identity::Config;

    // 1. Load the pre-enrolled `mfaspike` cert identity + its TOTP secret (fixture files; reusable).
    let identity_path =
        std::env::var("MFASPIKE_IDENTITY").unwrap_or_else(|_| "/tmp/mfaspike.json".into());
    let secret = std::env::var("MFASPIKE_SECRET").unwrap_or_else(|_| {
        std::fs::read_to_string("/tmp/mfaspike.secret")
            .unwrap_or_else(|_| "3HRE4SOYCP3NJEO5".into())
            .trim()
            .to_string()
    });
    let cfg: Config = serde_json::from_str(
        &std::fs::read_to_string(&identity_path).expect("read the mfaspike identity JSON"),
    )
    .expect("parse the mfaspike identity JSON");

    // 2. OIDC CERT grant WITH a TOTP provider. The login leg returns 200 + `totp-required`; the
    // provider mints a fresh code; the submit returns 302 → callback → token-exchange → Bearer.
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds from mfaspike");
    let provider = move || Ok(compute_totp(&secret));
    client
        .authenticate_oidc_with_totp(Some(&provider))
        .await
        .expect("OIDC cert + TOTP secondary auth completes (mfaspike is MFA-enrolled)");
    assert!(
        client.identity_name().is_some(),
        "MFA OIDC auth captured the id_token identity name"
    );

    // 3. connect over the (TOTP-completed) Bearer + cert control plane → plaintext round-trip echo.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("MFA connect(testsvc-noenc) succeeds after TOTP secondary auth");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-mfa-totp\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-mfa-totp\n"[..]),
        "MFA plaintext echo round-trips through the router after TOTP auth"
    );
    conn.close().await.expect("close MFA conn");
    println!(
        "MFA-1: OIDC cert + TOTP secondary auth + connect(testsvc-noenc) round-trip OK (identity={:?})",
        client.identity_name()
    );
}

/// LEGACY MFA (`/authenticate/mfa`, slice `feat/edge-mfa-midsession`): the LEGACY counterpart of
/// `mfaspike_oidc_totp_then_connect`. `mfaspike` authenticates by the LEGACY cert grant (NOT OIDC);
/// the controller returns a PARTIAL api-session (`authQueries` = `./authenticate/mfa`); the stored
/// `MfaCodeProvider` mints a fresh TOTP code; the SDK submits it to `POST /authenticate/mfa` and
/// re-fetches the now-completed session; then `connect(testsvc-noenc)` round-trips. This is the
/// faithful `authenticateMfa` path (`ziti.go:1365`), the 3rd `updateTokenOnAllErs` site (a LEGACY
/// gated NO-OP — `RequiresRouterTokenUpdate()` is false, so the live test cannot observe a token
/// push; its value is MFA-auth → connect round-trip). New wire = `/authenticate/mfa` submit.
#[tokio::test]
#[ignore = "requires a live controller + router + testsvc-noenc + the mfaspike MFA fixture; legacy /authenticate/mfa"]
async fn mfaspike_legacy_mfa_then_connect() {
    use noa_sdk::edge::client::MfaCodeProvider;
    use noa_sdk::enroll::identity::Config;
    use std::sync::Arc;

    // 1. Load the pre-enrolled `mfaspike` cert identity + its TOTP secret (reusable fixture files).
    let identity_path =
        std::env::var("MFASPIKE_IDENTITY").unwrap_or_else(|_| "/tmp/mfaspike.json".into());
    let secret = std::env::var("MFASPIKE_SECRET").unwrap_or_else(|_| {
        std::fs::read_to_string("/tmp/mfaspike.secret")
            .unwrap_or_else(|_| "3HRE4SOYCP3NJEO5".into())
            .trim()
            .to_string()
    });
    let cfg: Config = serde_json::from_str(
        &std::fs::read_to_string(&identity_path).expect("read the mfaspike identity JSON"),
    )
    .expect("parse the mfaspike identity JSON");

    // 2. LEGACY cert auth WITH a stored TOTP provider. The cert auth returns 200 + a non-empty
    // `authQueries`; the provider mints a fresh code; the SDK submits it to `/authenticate/mfa` and
    // re-fetches the completed session.
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds from mfaspike");
    let provider: MfaCodeProvider = Arc::new(move || Ok(compute_totp(&secret)));
    client
        .authenticate_with_totp(Some(provider))
        .await
        .expect("legacy cert + TOTP MFA completes (mfaspike is MFA-enrolled)");
    assert!(
        client.identity_name().is_some(),
        "legacy MFA auth captured the api-session identity name"
    );

    // 3. connect over the (MFA-completed) legacy token control plane → plaintext round-trip echo.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("legacy MFA connect(testsvc-noenc) succeeds after /authenticate/mfa");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-legacy-mfa\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-legacy-mfa\n"[..]),
        "legacy MFA plaintext echo round-trips through the router after /authenticate/mfa"
    );
    conn.close().await.expect("close legacy MFA conn");
    println!(
        "legacy MFA: cert auth + /authenticate/mfa + connect(testsvc-noenc) round-trip OK (identity={:?})",
        client.identity_name()
    );
}

/// Extract the base32 `secret` from a TOTP provisioning URL
/// (`otpauth://totp/...?issuer=...&secret=BASE32`). DEV-ONLY (the SDK never reads the secret).
fn secret_from_provisioning_url(url: &str) -> String {
    match url
        .split(['?', '&'])
        .find_map(|kv| kv.strip_prefix("secret="))
    {
        Some(s) => s.to_string(),
        None => panic!("no secret= in provisioning URL: {url}"),
    }
}

// ───────────────── enroll-at-login (TOTP MFA provisioning DURING login, batch objective 2) ─────────────────
//
// NEW wire (`/oidc/login/totp/enroll` 201 + provisioningUrl → `/oidc/login/totp/enroll/verify` 302) →
// live OBLIGATORY (live-validation rule: new wire needs a live test). UNLIKE `mfaspike_oidc_totp_then_connect` (an
// already-enrolled identity), this enrols a FRESH identity whose auth-policy REQUIRES TOTP but which has
// NOT yet enrolled: the OIDC login returns the enrollment challenge (`isTotpEnrolled` absent → not
// enrolled), the SDK starts enrollment, the test's enroll HANDLER extracts the NEW secret from the
// returned provisioning URL and computes the first verification code → enrollment completes inline →
// login completes → connect round-trip.
//
// SINGLE-USE per identity (once enrolled it is enrolled) → this test MUST run against a FRESH identity
// each run. Reusable infra + the per-run recipe (default controller in OrbStack):
//
//   # one-time reusable auth-policy (cert primary + TOTP secondary required):
//   ziti edge create auth-policy noaMfaEnrollPolicy --primary-cert-allowed \
//       --primary-ext-jwt-allowed=false --secondary-req-totp
//   POLICY=$(ziti edge list auth-policies 'name="noaMfaEnrollPolicy"' -j | \
//       python3 -c "import sys,json;print(json.load(sys.stdin)['data'][0]['id'])")
//
//   # PER RUN: a fresh identity under that policy (the OTT JWT is what the test enrols):
//   N=noaMfaEnroll$RANDOM
//   ziti edge create identity "$N" -a noatest --auth-policy "$POLICY" -o /tmp/$N.jwt
//   ZITI_MFA_ENROLL_JWT=/tmp/$N.jwt cargo test --test edge_integration \
//       enrol_mfa_at_login_then_connect -- --ignored --nocapture
//   ziti edge delete identity "$N"     # cleanup (the OTT was consumed by the enrol)
//
// `noatest` is the role testsvc-noenc dial policy grants (see "Infra viva en OrbStack").
#[tokio::test]
#[ignore = "requires a live OIDC controller + router + testsvc-noenc + a FRESH identity under noaMfaEnrollPolicy (ZITI_MFA_ENROLL_JWT); enroll-at-login"]
async fn enrol_mfa_at_login_then_connect() {
    // 1. Enrol a FRESH identity (under the TOTP-requiring auth-policy) with our crate → cert identity.
    let jwt = std::fs::read_to_string(env_path("ZITI_MFA_ENROLL_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment of the fresh MFA-policy identity succeeds");

    // 2. OIDC CERT grant WITH an ENROLL HANDLER (no code provider — the identity is NOT yet enrolled).
    //    The login leg returns 200 + `totp-required` (`isTotpEnrolled` absent → not enrolled); the SDK
    //    POSTs `/oidc/login/totp/enroll` (201 + provisioningUrl); the handler extracts the NEW secret
    //    and computes the FIRST code; the SDK POSTs `/oidc/login/totp/enroll/verify` (302) → login
    //    completes → Bearer.
    let mut client =
        EdgeClient::from_identity(&cfg).expect("mTLS client builds from the fresh identity");
    let enroll_handler = move |provisioning_url: &str| {
        let secret = secret_from_provisioning_url(provisioning_url);
        Ok(compute_totp(&secret))
    };
    client
        .authenticate_oidc_with_mfa(None, Some(&enroll_handler))
        .await
        .expect(
            "OIDC cert + inline TOTP enrollment completes (fresh identity provisions MFA at login)",
        );
    assert!(
        client.identity_name().is_some(),
        "enroll-at-login OIDC auth captured the id_token identity name"
    );

    // 3. connect over the (enrollment-completed) Bearer + cert control plane → plaintext round-trip.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect(testsvc-noenc) succeeds after inline TOTP enrollment");
    assert!(conn.circuit_id().is_some(), "plaintext circuit established");
    conn.write(b"hello-mfa-enroll\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-mfa-enroll\n"[..]),
        "plaintext echo round-trips through the router after enroll-at-login"
    );
    conn.close().await.expect("close enroll-at-login conn");
    println!(
        "enroll-at-login: OIDC cert + inline TOTP enroll + connect(testsvc-noenc) round-trip OK (identity={:?})",
        client.identity_name()
    );
}

/// Tunneler T1 (proxy-TCP) end-to-end: a local TCP listener spliced onto a ziti service. For BOTH a
/// plaintext (`testsvc-noenc`) and an encrypted (`testsvc`) service — exercising the data-plane
/// read/write split + the crypto partition in both directions over a real router — open a TCP client
/// through the proxy, round-trip an echo, then half-close and confirm the socket sees EOF.
#[tokio::test]
#[ignore = "requires a live controller + online router + hosted testsvc/testsvc-noenc; see docs/edge-integration.md"]
async fn enrol_then_proxy_tcp_round_trip() {
    use noa_sdk::tunnel::run_tcp_proxy;
    use std::rc::Rc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");
    let client = Rc::new(client);

    for service in ["testsvc-noenc", "testsvc"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy_client = Rc::clone(&client);
        let svc = service.to_string();

        tokio::task::LocalSet::new()
            .run_until(async move {
                // The proxy accept loop runs in the background of the LocalSet.
                let proxy = tokio::task::spawn_local(run_tcp_proxy(proxy_client, listener, svc));

                // Act as a local TCP client through the proxy.
                let mut tcp = TcpStream::connect(addr).await.expect("connect to proxy");
                let payload = format!("hello-proxy-{service}\n");
                tcp.write_all(payload.as_bytes()).await.expect("write");
                let mut buf = vec![0u8; payload.len()];
                tcp.read_exact(&mut buf)
                    .await
                    .expect("read echo through proxy");
                assert_eq!(
                    buf,
                    payload.as_bytes(),
                    "{service}: echo round-trips through the TCP proxy"
                );
                // Half-close the client write -> proxy forwards a FIN to ziti -> the echo service
                // closes -> the proxy half-closes the socket -> our read sees EOF.
                tcp.shutdown().await.expect("client half-close");
                let mut rest = Vec::new();
                tcp.read_to_end(&mut rest)
                    .await
                    .expect("drain socket to EOF");
                proxy.abort();
            })
            .await;
        println!("tunneler T1 proxy round-trip OK for '{service}'");
    }
}

/// Tunneler T2 (host-TCP) end-to-end, run against the REAL `run_tcp_host` accept loop: this identity
/// hosts a ziti `service` (`bind`) and forwards each inbound dial to an in-process local TCP echo.
/// A separate dialer identity `connect`s the service (routed by the controller to OUR host), and the
/// payload round-trips dialer → router → our host → local TCP echo → back. Exercises the host
/// direction of bind/accept + the reused `splice` (the encrypted service also exercises the crypto
/// partition through the splice host-side). Two single-use OTT identities (host = `ZITI_EDGE_JWT`,
/// dialer = `ZITI_EDGE_JWT_DIALER`) — run ONE host test per invocation with fresh JWTs.
#[cfg(test)]
async fn run_host_tcp_live(service: &str, payload: &[u8]) {
    use noa_sdk::tunnel::run_tcp_host;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // In-process echo target: the host forwards every accepted child here. Echoes each chunk and
    // half-closes its write on the peer's EOF (so the dialer's half-close propagates end-to-end).
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host identity: enrol, auth, bind(service).
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let binding = host.bind(service).await.expect("bind(service) succeeds");
    println!("host bound '{service}': conn_id={}", binding.conn_id());

    // Dialer identity: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // Run the REAL host accept loop in the background of a LocalSet (run_tcp_host uses spawn_local,
    // which needs a LocalSet); the dialer round-trip is the awaited future, so when it completes
    // run_until returns -> the LocalSet drops -> the host loop + its child splices are aborted.
    let svc = service.to_string();
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host(binding, echo_addr));

            let mut dconn = dialer.connect(&svc).await.expect("dialer connect(service)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH our run_tcp_host -> local TCP echo"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!("tunneler T2 host-TCP round-trip OK for '{service}'");
}

/// T2 host-TCP, plaintext service (`bindsvc`).
#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc (Bind+Dial policies) + 2 JWTs; tunneler T2; pre-flight: scripts/rig-fixtures.sh"]
async fn bind_then_host_tcp_round_trip() {
    run_host_tcp_live("bindsvc", b"hello-host-t2\n").await;
}

/// T2 host-TCP, encrypted service (`bindsvc-enc`) — exercises the crypto partition through the splice
/// in the host direction (server-side e2e crypto from 7b-2 + the read/write split from T1).
#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc-enc (encryptionRequired=true, Bind+Dial policies) + 2 JWTs; tunneler T2; pre-flight: scripts/rig-fixtures.sh"]
async fn bind_then_host_tcp_encrypted_round_trip() {
    run_host_tcp_live("bindsvc-enc", b"hello-host-t2-enc\n").await;
}

/// Tunneler T3 (proxy-UDP) end-to-end, run against the REAL `run_udp_proxy` manager: a proxy identity
/// runs the UDP proxy on a local socket onto a ziti `service`; a host identity `bind`s the service and
/// echoes each accepted `EdgeConn`'s chunks back (an in-process ziti echo — the proxy is what we are
/// validating). A local UDP client sends a datagram to the proxy, which dials ziti, forwards the
/// datagram as a Data frame, the host echoes it, and the proxy sends it back to the client's source
/// address. Exercises the new datagram↔Data-frame data-plane (and, for `bindsvc-enc`, the crypto
/// partition in both directions). Two single-use OTT identities (host = `ZITI_EDGE_JWT`, proxy =
/// `ZITI_EDGE_JWT_DIALER`) — run ONE proxy-UDP test per invocation with fresh JWTs.
#[cfg(test)]
async fn run_proxy_udp_live(service: &str, payload: &[u8]) {
    use noa_sdk::tunnel::run_udp_proxy;
    use std::rc::Rc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    // Host identity: enrol, auth, bind(service) — the in-process ziti echo's listener.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let mut binding = host.bind(service).await.expect("bind(service) succeeds");
    println!("host bound '{service}': conn_id={}", binding.conn_id());

    // Proxy identity: enrol, auth — the identity the UDP proxy dials with.
    let proxy_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let proxy_cfg = enroll::ott::enroll(proxy_jwt.trim(), EnrollOptions::default())
        .await
        .expect("proxy enrolment succeeds");
    let mut proxy_client = EdgeClient::from_identity(&proxy_cfg).expect("proxy mTLS client builds");
    proxy_client
        .authenticate()
        .await
        .expect("proxy authenticate");
    let proxy_client = Rc::new(proxy_client);

    // The proxy's local UDP listener (the client sends here).
    let proxy_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let svc = service.to_string();
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            // In-process ziti echo: accept each inbound dial and echo its chunks back to ziti.
            let host_loop = tokio::task::spawn_local(async move {
                while let Ok(mut child) = binding.accept().await {
                    tokio::task::spawn_local(async move {
                        while let Ok(Some(chunk)) = child.read().await {
                            if child.write(&chunk).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            // The REAL proxy-UDP manager.
            let proxy = tokio::task::spawn_local(run_udp_proxy(proxy_client, proxy_sock, svc));

            // Act as a local UDP client through the proxy.
            let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_sock
                .send_to(&payload, proxy_addr)
                .await
                .expect("send datagram to the proxy");
            let mut buf = vec![0u8; 65507];
            let (n, _from) =
                tokio::time::timeout(Duration::from_secs(20), client_sock.recv_from(&mut buf))
                    .await
                    .expect("recv did not time out")
                    .expect("recv the echoed datagram");
            assert_eq!(
                &buf[..n],
                payload.as_slice(),
                "datagram round-trips THROUGH our run_udp_proxy -> ziti -> in-process echo"
            );

            proxy.abort();
            host_loop.abort();
        })
        .await;
    println!("tunneler T3 proxy-UDP round-trip OK for '{service}'");
}

/// T3 proxy-UDP, plaintext service (`bindsvc`).
#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc (Bind+Dial policies) + 2 JWTs; tunneler T3; pre-flight: scripts/rig-fixtures.sh"]
async fn enrol_then_proxy_udp_round_trip() {
    run_proxy_udp_live("bindsvc", b"hello-proxy-udp-t3").await;
}

/// T3 proxy-UDP, encrypted service (`bindsvc-enc`) — exercises the crypto partition in both directions
/// (client crypto on the proxy's dial + server crypto on the host's accept) through the UDP data-plane.
#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc-enc (encryptionRequired=true, Bind+Dial policies) + 2 JWTs; tunneler T3; pre-flight: scripts/rig-fixtures.sh"]
async fn enrol_then_proxy_udp_encrypted_round_trip() {
    run_proxy_udp_live("bindsvc-enc", b"hello-proxy-udp-t3-enc").await;
}

/// T4a (faithful accept-then-dial split): a host whose target is UNREACHABLE now sends DialFailed
/// (it dials the target BEFORE acknowledging), instead of the pre-split eager DialSuccess that the
/// target-unreachable path then closed with StateClosed. CONFIRMS the live wire payoff (the advisor's
/// "do not assume"): we OBSERVE what the dialer sees — `connect()` returning `Err` (the DialFailed
/// propagated as a dial rejection) is the strong outcome; if instead the router establishes the
/// circuit and the host's DialFailed surfaces as a teardown, `connect()` succeeds but yields NO usable
/// connection (immediate EOF). Either way the dialer gets no usable conn (the real guarantee); the run
/// prints which the router does. Two single-use OTT identities (host = `ZITI_EDGE_JWT`, dialer =
/// `ZITI_EDGE_JWT_DIALER`).
#[tokio::test]
#[ignore = "requires a live controller + online router + bindsvc (Bind+Dial policies) + 2 JWTs; tunneler T4a; pre-flight: scripts/rig-fixtures.sh"]
async fn bind_then_host_tcp_target_unreachable_fails_dial() {
    use noa_sdk::tunnel::run_tcp_host;
    use std::time::Duration;

    // Host: enrol, auth, bind(bindsvc) — but its target will be unreachable.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let binding = host.bind("bindsvc").await.expect("bind(bindsvc) succeeds");

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // A definitely-dead local target (bind then drop → ECONNREFUSED at the host).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap().to_string();
    drop(l);

    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host(binding, dead));
            let res = tokio::time::timeout(Duration::from_secs(20), dialer.connect("bindsvc"))
                .await
                .expect("dialer connect did not time out");
            host_loop.abort();
            match res {
                Err(e) => {
                    println!("T4a OK live: target-unreachable → dialer connect() FAILED (DialFailed propagated): {e:?}");
                }
                Ok(mut conn) => {
                    // The router established the circuit before the host's DialFailed; the host's
                    // failure must surface as an immediate teardown → NO usable round-trip.
                    let _ = conn.write(b"should-not-echo").await;
                    let got = tokio::time::timeout(Duration::from_secs(5), conn.read())
                        .await
                        .expect("read did not time out");
                    assert!(
                        matches!(got, Ok(None) | Err(_)),
                        "T4a: an unreachable host target must NOT yield a usable connection (got {got:?})"
                    );
                    println!("T4a live: connect() succeeded but no usable conn (immediate EOF) — router establishes the circuit, host DialFailed surfaces as teardown");
                }
            }
        })
        .await;
}

// T4b-0 (service-config retrieval): the NEW configTypes wire on the service list. Per
// the live-validation rule the new query param needs live proof: enrol → authenticate →
// `list_services_with_config_types(["host.v1","intercept.v1"])` → the controller populates each
// service's `config`, and `Service::host_v1_config()` parses the REAL host.v1 JSON. testsvc /
// testsvc-noenc carry the `noenc-host`/`enc-host` host.v1 (localhost:19009 tcp); bindsvc has none.
// A `list_services()` WITHOUT config types returns empty configs (the gap this slice closes) — also
// asserted, so the test pins that the configTypes param is what makes the difference (not luck).
#[tokio::test]
#[ignore = "requires a live OpenZiti controller (OrbStack); validates the configTypes service-list wire"]
async fn enrol_then_list_service_configs() {
    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // WITHOUT config types → configs are empty (the pre-T4b-0 behaviour, what we're fixing).
    let plain = client.list_services().await.expect("list services");
    for s in &plain {
        assert!(
            s.config.is_empty(),
            "without configTypes the controller returns no config for {} (got {:?})",
            s.name,
            s.config.keys().collect::<Vec<_>>()
        );
    }

    // WITH config types → host.v1 (and intercept.v1) populate and parse.
    let svcs = client
        .list_services_with_config_types(&["host.v1".to_string(), "intercept.v1".to_string()])
        .await
        .expect("list services with config types");
    let find = |name: &str| svcs.iter().find(|s| s.name == name).cloned();

    let testsvc = find("testsvc").expect("testsvc visible");
    let hv1 = testsvc
        .host_v1_config()
        .expect("host.v1 parses")
        .expect("testsvc has a host.v1 config");
    assert_eq!(hv1.address, "localhost", "testsvc host.v1 address");
    assert_eq!(hv1.port, 19009, "testsvc host.v1 port");
    assert_eq!(hv1.protocol, "tcp", "testsvc host.v1 protocol");

    let noenc = find("testsvc-noenc").expect("testsvc-noenc visible");
    assert!(
        noenc.host_v1_config().expect("parses").is_some(),
        "testsvc-noenc has a host.v1 config when requested"
    );

    // bindsvc has no host.v1 config assigned → None (not an error).
    if let Some(bindsvc) = find("bindsvc") {
        assert!(
            bindsvc.host_v1_config().expect("parses").is_none(),
            "bindsvc has no host.v1 config"
        );
    }
    println!(
        "T4b-0 OK live: configTypes wire populates host.v1 (testsvc {}:{} {}); plain list stays empty",
        hv1.address, hv1.port, hv1.protocol
    );
}

/// Tunneler T4b-1 (appData → host.v1 forwarding) end-to-end, run against the REAL
/// `run_tcp_host_forwarding` accept loop + a REAL appData dialer. Per the live-validation rule the
/// new wire (header 1011 emitted by the dialer + the host reading it to resolve a DYNAMIC target) needs
/// live proof in BOTH directions.
///
/// The host hosts a `forwardAddress`+`forwardPort` service (`fwdsvc`, `host.v1`
/// `{"protocol":"tcp","forwardAddress":true,"allowedAddresses":["127.0.0.1/32"],"forwardPort":true,
/// "allowedPortRanges":[{"low":1,"high":65535}]}`), reads that host.v1 via `list_services_with_config_types`,
/// and runs the forwarding host. The dialer `connect_with_appdata`s with `dst_ip`/`dst_port` pointing at
/// an in-process TCP echo (the host dials it DYNAMICALLY from the appData — there is no fixed target).
/// The payload round-trips dialer → router → host → resolved local echo → back. Two single-use OTT
/// identities (host = `ZITI_EDGE_JWT`, dialer = `ZITI_EDGE_JWT_DIALER`).
///
/// Rig (mirror the bindsvc rig in `docs/edge-integration.md`):
/// `ziti edge create config fwdsvc-host host.v1 '{"protocol":"tcp","forwardAddress":true,
/// "allowedAddresses":["127.0.0.1/32"],"forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}]}'`
/// then `ziti edge create service fwdsvc -c fwdsvc-host -e OFF`.
/// **CRITICAL — scope Bind so ONLY our SDK host serves:** because the host.v1 config makes er1's
/// tunneler auto-host fwdsvc (host-networking → er1's `127.0.0.1` IS the Mac's), a `#all` Bind policy
/// would let er1 compete for the terminator and (smartrouting) possibly serve the round-trip itself —
/// the test would pass WITHOUT exercising our host-side appData reader. So the host identity gets an
/// attribute and Bind is scoped to it: `ziti edge create identity <host> -a t4bhost -o ...` +
/// `ziti edge create service-policy bind-fwdsvc Bind --service-roles '@fwdsvc' --identity-roles
/// '#t4bhost'`; Dial stays `#all` (`dial-fwdsvc`). er1 then has no Bind on fwdsvc → its terminator
/// disappears → the round-trip can ONLY be served by our `run_tcp_host_forwarding` (= our
/// `accept_pending` 1011-read + `resolve_target`). The DIALER identity needs no attribute.
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc (host.v1 forwardAddress, Bind+Dial policies) + 2 JWTs; tunneler T4b-1"]
async fn bind_then_host_forward_appdata_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc";
    let payload = b"hello-forward-t4b1\n";

    // In-process echo: the DYNAMIC target the host resolves from the dialer's appData. Bound to a
    // loopback ephemeral port (allowed by the fwdsvc host.v1: 127.0.0.1/32 + ports 1..=65535).
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc's host.v1, bind, run the forwarding host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect("fwdsvc host.v1 parses")
        .expect("fwdsvc has a host.v1 forwardAddress config");
    assert!(
        host_v1.forward_address && host_v1.forward_port,
        "fwdsvc is a forwardAddress+forwardPort service"
    );
    let binding = host.bind(SERVICE).await.expect("bind(fwdsvc) succeeds");
    println!("host bound '{SERVICE}': conn_id={}", binding.conn_id());

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // The appData pointing the host at the in-process echo (the dynamic target).
    let app_data = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        None,
    );
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding -> appData-resolved local TCP echo"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-1 OK live: appData (dst_ip={} dst_port={}) drove a dynamic host dial; round-trip OK",
        echo_addr.ip(),
        echo_addr.port()
    );
}

/// Tunneler T4b-2d-2 (`source_addr` socket bind) end-to-end, against the REAL `run_tcp_host_forwarding`.
/// The dialer's appData carries a `source_addr` (`127.0.0.1:<reserved port>`), so the host binds the
/// LOCAL end of its outbound dial to that port (`net.Dialer{LocalAddr}`). The in-process echo records the
/// connecting peer; the round-trip succeeds AND the echo's observed peer PORT == the requested source port
/// — a POSITIVE proof the bind took effect (a default-source dial would show a random ephemeral port). The
/// source IP is loopback either way (the host + echo run on the Mac; `127.0.0.2` is not bindable without
/// aliasing `lo0`), so the PORT is the observable.
///
/// REUSES the `fwdsvc` rig (no new host.v1): `source_addr` is per-dial appData, not config, and the
/// oracle does NOT check it against the allow-list. `fwdsvc`'s `allowedAddresses:["127.0.0.1/32"]` +
/// `allowedPortRanges:[1..65535]` already admit the loopback echo target. Two single-use OTT identities
/// (host = `ZITI_EDGE_JWT` with `-a t4bhost`, dialer = `ZITI_EDGE_JWT_DIALER`). See
/// `bind_then_host_forward_appdata_round_trip` + `docs/edge-integration.md` for the rig.
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc (host.v1 forwardAddress, Bind+Dial policies) + 2 JWTs; tunneler T4b-2d-2"]
#[allow(clippy::too_many_lines)] // full live round-trip + the load-bearing source-port assertion
async fn bind_then_host_forward_source_addr_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc";
    let payload = b"hello-srcbind-t4b2d2\n";

    // Reserve a free loopback port to use as the dial's SOURCE port (bind a listener to :0, take its
    // port, drop it — a never-accepted listening socket frees the port with no TIME_WAIT).
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_port = probe.local_addr().unwrap().port();
    drop(probe);

    // In-process echo (the dynamic target) that records the connecting peer via a oneshot.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    let mut peer_tx = Some(peer_tx);
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, peer)) = echo_listener.accept().await else {
                return;
            };
            if let Some(tx) = peer_tx.take() {
                let _ = tx.send(peer);
            }
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc's host.v1, bind, run the forwarding host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect("fwdsvc host.v1 parses")
        .expect("fwdsvc has a host.v1 forwardAddress config");
    let binding = host.bind(SERVICE).await.expect("bind(fwdsvc) succeeds");
    println!("host bound '{SERVICE}': conn_id={}", binding.conn_id());

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // appData: dst_ip/dst_port → the echo; source_addr → 127.0.0.1:<src_port> (the host binds its dial).
    let app_data = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        Some(&format!("127.0.0.1:{src_port}")),
    );
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding -> source-bound host dial -> echo"
            );

            // The load-bearing assertion: the echo saw the host's dial coming from the REQUESTED source
            // port (a default-source dial would be a random ephemeral port).
            let peer = tokio::time::timeout(Duration::from_secs(5), peer_rx)
                .await
                .expect("peer observed before timeout")
                .expect("echo recorded the connecting peer");
            assert_eq!(
                peer.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                "host's dial sourced from loopback"
            );
            assert_eq!(
                peer.port(),
                src_port,
                "host bound its dial's local end to the requested source_addr port (net.Dialer LocalAddr)"
            );

            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-2d-2 OK live: source_addr=127.0.0.1:{src_port} bound the host dial; echo saw that exact source port; round-trip OK"
    );
}

/// Tunneler T4b-2d-1 (`forwardAddressTranslations`) end-to-end: the dialer's `dst_ip` resolves to an
/// address INSIDE the allow-list, but the host's `host.v1` `forwardAddressTranslations` renumbers it
/// onto a DIFFERENT network before dialing. The round-trip succeeds ONLY because the host applied the
/// translation — a host that dialed the pre-translation `dst_ip` would hit nothing → no echo. So a green
/// round-trip PROVES the translation fired against the REAL `run_tcp_host_forwarding` + the REAL host.v1
/// served by the controller.
///
/// This adds NO new wire (the appData/Connect frame is identical to T4b-1 — the host just dials a
/// DIFFERENT target). Per the live-validation rule the new RESOLUTION logic is unit/differential
/// tested; this live round-trip exercises the wrapper end-to-end AND resolves the WATCH-ITEM: does the
/// OrbStack controller serve a `host.v1` with `forwardAddressTranslations` back via
/// `list_services_with_config_types`? (T4b-0 confirmed `forwardAddress`, T4b-2c `connectTimeout`; this is
/// the first slice reading `forwardAddressTranslations` live. The controller schema
/// `migration_initialize.go:297-321` defines `ipv4AddressTranslation` (from/to ipv4, prefixLength 0-32),
/// so it SHOULD accept + serve it; if the serde does not populate the field, fall back to the unit/
/// differential coverage + the `bind_then_host_forward_appdata_round_trip` neighbor and report it.)
///
/// The service `fwdsvc-xlat` hosts a `forwardAddress`+`forwardPort` host.v1 whose `allowedAddresses`
/// includes `10.0.0.0/8` (the PRE-translation network) and whose `forwardAddressTranslations` maps
/// `10.0.0.0/24 → 127.0.0.0/24`. The dialer sends `dst_ip=10.0.0.1` (allowed) + `dst_port=<echo port>`;
/// the host renumbers `10.0.0.1 → 127.0.0.1` (the in-process echo on loopback) and round-trips. Two
/// single-use OTT identities (host = `ZITI_EDGE_JWT` with attribute `t4bhost`, dialer =
/// `ZITI_EDGE_JWT_DIALER`).
///
/// Rig (a sibling of the `fwdsvc` rig — see `bind_then_host_forward_appdata_round_trip` + the OrbStack
/// live-rig recipe; scope the Bind to `#t4bhost` so ONLY our SDK host serves it, else er1's auto-host
/// could win the terminator and serve the round-trip WITHOUT our translation):
/// `ziti edge create config fwdsvc-xlat-host host.v1 '{"protocol":"tcp","forwardAddress":true,
/// "allowedAddresses":["10.0.0.0/8"],"forwardAddressTranslations":[{"from":"10.0.0.0","to":"127.0.0.0",
/// "prefixLength":24}],"forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}]}'` then
/// `ziti edge create service fwdsvc-xlat -c fwdsvc-xlat-host -e OFF` +
/// `ziti edge create service-policy bind-fwdsvc-xlat Bind --service-roles '@fwdsvc-xlat' --identity-roles
/// '#t4bhost'` + `ziti edge create service-policy dial-fwdsvc-xlat Dial --service-roles '@fwdsvc-xlat'
/// --identity-roles '#all'`.
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc-xlat (host.v1 forwardAddressTranslations, Bind+Dial policies) + 2 JWTs; tunneler T4b-2d-1"]
async fn bind_then_host_forward_translation_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc-xlat";
    let payload = b"hello-translated-t4b2d1\n";

    // In-process echo on loopback — the POST-translation target. The translation `10.0.0.0/24 →
    // 127.0.0.0/24` maps the dialer's `dst_ip=10.0.0.1` to `127.0.0.1`; the echo MUST be on 127.0.0.1.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    assert!(echo_addr.ip().is_loopback(), "echo must be on 127.0.0.1");
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc-xlat's host.v1 (WITH the translation), bind, run the forwarding host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect("fwdsvc-xlat host.v1 parses")
        .expect("fwdsvc-xlat has a host.v1 forwardAddress config");
    // WATCH-ITEM resolution: the controller must serve the translation back, else the host would dial
    // the pre-translation 10.0.0.1 and the round-trip would fail.
    assert!(
        !host_v1.forward_address_translations.is_empty(),
        "fwdsvc-xlat host.v1 carries forwardAddressTranslations (controller serves the field)"
    );
    let binding = host
        .bind(SERVICE)
        .await
        .expect("bind(fwdsvc-xlat) succeeds");
    println!("host bound '{SERVICE}': conn_id={}", binding.conn_id());

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // appData: dst_ip=10.0.0.1 (allowed by 10.0.0.0/8), dst_port=<echo port>. The host translates the
    // address to 127.0.0.1 and dials the echo; the dst_port is NOT translated (forwardPort path).
    let app_data = build_app_data("tcp", "10.0.0.1", &echo_addr.port().to_string(), None, None);
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc-xlat)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding -> TRANSLATED target (10.0.0.1->127.0.0.1) echo"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-2d-1 OK live: forwardAddressTranslations renumbered dst_ip=10.0.0.1 -> 127.0.0.1:{}; round-trip OK",
        echo_addr.port()
    );
}

/// Tunneler T4b-2a (matchers string-vs-IP) end-to-end: the dialer sends a `dst_hostname` (NOT a
/// `dst_ip`), and the host STRING-matches it against the service's `host.v1` `allowedAddresses`
/// hostname/domain matchers, then dials the resolved hostname. The new wire is the dialer emitting a
/// `dst_hostname` key in appData (header 1011) + the host reading it and string-matching it — distinct
/// from T4b-1's `dst_ip`/CIDR path. Per the live-validation rule the new string-match wire needs
/// live proof.
///
/// The service `fwdsvc-hn` hosts a `forwardAddress`+`forwardPort` host.v1 whose `allowedAddresses`
/// includes the HOSTNAME `"localhost"` (a `hostnameAddress` string matcher — a CIDR would NOT match a
/// `dst_hostname` string, that is the crux). The dialer `connect_with_appdata`s with
/// `dst_hostname="localhost"` + `dst_port=<echo port>`; the host resolves `localhost` (→ the in-process
/// echo on `127.0.0.1`) and round-trips. Two single-use OTT identities (host = `ZITI_EDGE_JWT` with
/// attribute `t4bhost`, dialer = `ZITI_EDGE_JWT_DIALER`).
///
/// Rig (a sibling of the `fwdsvc` rig — see `bind_then_host_forward_appdata_round_trip` + the OrbStack
/// live-rig recipe). Create a hostname-allow-list host.v1 + service, and scope the Bind to our host so
/// ONLY our SDK serves it (else er1's auto-host could win the terminator):
/// `ziti edge create config fwdsvc-hn-host host.v1 '{"protocol":"tcp","forwardAddress":true,
/// "allowedAddresses":["localhost"],"forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}]}'`
/// then `ziti edge create service fwdsvc-hn -c fwdsvc-hn-host -e OFF`,
/// `ziti edge create service-policy bind-fwdsvc-hn Bind --service-roles '@fwdsvc-hn' --identity-roles
/// '#t4bhost'` and `ziti edge create service-policy dial-fwdsvc-hn Dial --service-roles '@fwdsvc-hn'
/// --identity-roles '#all'`. The host identity is enrolled with `-a t4bhost` (same as the fwdsvc host).
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc-hn (host.v1 forwardAddress hostname allow-list, Bind+Dial policies) + 2 JWTs; tunneler T4b-2a"]
async fn bind_then_host_forward_hostname_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc-hn";
    const DST_HOSTNAME: &str = "localhost";
    let payload = b"hello-forward-hostname-t4b2a\n";

    // In-process echo on loopback; the host will resolve "localhost" → 127.0.0.1 and dial THIS port.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc-hn's host.v1 (hostname allow-list), bind, run the forwarding host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect("fwdsvc-hn host.v1 parses")
        .expect("fwdsvc-hn has a host.v1 forwardAddress config");
    assert!(
        host_v1.forward_address && host_v1.allowed_addresses.iter().any(|a| a == DST_HOSTNAME),
        "fwdsvc-hn host.v1 forwards with a hostname allow-list entry"
    );
    let binding = host.bind(SERVICE).await.expect("bind(fwdsvc-hn) succeeds");

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // appData with a dst_HOSTNAME (string-matched). dst_ip is present but the host tries hostname FIRST.
    let app_data = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        Some(DST_HOSTNAME),
        None,
    );
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc-hn)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding -> dst_hostname-resolved local TCP echo"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-2a OK live: dst_hostname={DST_HOSTNAME} string-matched + resolved; round-trip OK"
    );
}

/// Tunneler T4b-2b (forwardProtocol) end-to-end: the host hosts a service whose `host.v1` sets
/// `forwardProtocol:true` + `allowedProtocols:["tcp"]`, so the host resolves the dial PROTOCOL from the
/// inbound appData `dst_protocol` (validated against `allowedProtocols`) instead of a fixed `protocol`.
///
/// NOTE on live obligation (live-validation rule: new wire needs a live test): T4b-2b is NOT new wire — `dst_protocol` was
/// already emitted by `build_app_data` and validated live in `bind_then_host_forward_appdata_round_trip`
/// (T4b-1), and the `forwardProtocol`/`allowedProtocols` config fields parse via the T4b-0 config wire. So
/// obligatory live is NOT required. This test exists to confirm the ONE thing the unit tests cannot: that
/// the controller SERVES a `forwardProtocol:true` host.v1 the way our serde parses it, and that the host's
/// `GetProtocol` resolves `dst_protocol` end-to-end. The dialer's appData already carries `dst_protocol=tcp`.
///
/// Rig (a sibling of the `fwdsvc` rig — see `bind_then_host_forward_appdata_round_trip` + the OrbStack
/// recipe in `docs/edge-integration.md`):
/// `ziti edge create config fwdsvc-fp-host host.v1 '{"protocol":"tcp","forwardProtocol":true,
/// "allowedProtocols":["tcp"],"forwardAddress":true,"allowedAddresses":["127.0.0.1/32"],
/// "forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}]}'`
/// then `ziti edge create service fwdsvc-fp -c fwdsvc-fp-host -e OFF`,
/// `ziti edge create service-policy bind-fwdsvc-fp Bind --service-roles '@fwdsvc-fp' --identity-roles
/// '#t4bhost'` and `ziti edge create service-policy dial-fwdsvc-fp Dial --service-roles '@fwdsvc-fp'
/// --identity-roles '#all'`. The host identity is enrolled with `-a t4bhost` (same as the fwdsvc host).
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc-fp (host.v1 forwardProtocol allowedProtocols, Bind+Dial policies) + 2 JWTs; tunneler T4b-2b"]
async fn bind_then_host_forward_protocol_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc-fp";
    let payload = b"hello-forward-protocol-t4b2b\n";

    // In-process echo: the DYNAMIC target the host resolves from the dialer's appData.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc-fp's host.v1 (forwardProtocol allow-list), bind, run forwarding host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect("fwdsvc-fp host.v1 parses")
        .expect("fwdsvc-fp has a host.v1 forwardProtocol config");
    assert!(
        host_v1.forward_protocol && host_v1.allowed_protocols.iter().any(|p| p == "tcp"),
        "fwdsvc-fp forwards the protocol with a tcp allow-list"
    );
    let binding = host.bind(SERVICE).await.expect("bind(fwdsvc-fp) succeeds");
    println!("host bound '{SERVICE}': conn_id={}", binding.conn_id());

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // appData carries dst_protocol=tcp (validated against allowedProtocols) + dst_ip/dst_port.
    let app_data = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        None,
    );
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc-fp)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding -> forwardProtocol-resolved tcp dial"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-2b OK live: forwardProtocol resolved dst_protocol=tcp against allowedProtocols; round-trip OK"
    );
}

/// T4b-2c LIVE — `connectTimeout` override of the host dial timeout.
///
/// This is config-driven host-side logic over the host.v1 config wire ALREADY validated by T4b-0, so per
/// the live-validation rule (live-validation rule: new wire needs a live test) the timeout LOGIC is unit-tested
/// (resolve/tests_timeout.rs's `get_dial_timeout` battery + host/tests_fixed.rs's threading killer) and
/// the obligatory live is NOT required for it.
/// The ONE thing only a live run can confirm — and the advisor flagged it as load-bearing — is the WIRE
/// SHAPE: that the controller ACCEPTS and SERVES a `host.v1` with `listenOptions.connectTimeout` as a
/// STRING our `Option<String>` serde parses (if it round-tripped as a number, e.g. nanoseconds, the model
/// would need a change → a re-slice signal, surfaced here as a hard parse error, not a silent pass). So
/// this test ASSERTS the parsed `connectTimeout` round-trips as `"10s"`, then does the round-trip through
/// the REAL `run_tcp_host_forwarding` (which resolves the timeout via `get_dial_timeout` at startup).
///
/// Rig (a sibling of the `fwdsvc-fp` rig — see `bind_then_host_forward_protocol_round_trip` + the OrbStack
/// recipe in `docs/edge-integration.md`):
/// `ziti edge create config fwdsvc-ct-host host.v1 '{"protocol":"tcp","forwardAddress":true,
/// "allowedAddresses":["127.0.0.1/32"],"forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}],
/// "listenOptions":{"connectTimeout":"10s"}}'`
/// then `ziti edge create service fwdsvc-ct -c fwdsvc-ct-host -e OFF`,
/// `ziti edge create service-policy bind-fwdsvc-ct Bind --service-roles '@fwdsvc-ct' --identity-roles
/// '#t4bhost'` and `ziti edge create service-policy dial-fwdsvc-ct Dial --service-roles '@fwdsvc-ct'
/// --identity-roles '#all'`. The host identity is enrolled with `-a t4bhost` (same as the fwdsvc host).
#[tokio::test]
#[ignore = "requires a live controller + online router + fwdsvc-ct (host.v1 listenOptions.connectTimeout, Bind+Dial policies) + 2 JWTs; tunneler T4b-2c"]
#[allow(clippy::too_many_lines)] // full live round-trip + the load-bearing wire-shape assertion
async fn bind_then_host_forward_connect_timeout_round_trip() {
    use noa_sdk::edge::dial::build_app_data;
    use noa_sdk::tunnel::run_tcp_host_forwarding;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SERVICE: &str = "fwdsvc-ct";
    let payload = b"hello-connect-timeout-t4b2c\n";

    // In-process echo: the DYNAMIC target the host resolves from the dialer's appData.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    // Host: enrol, auth, read fwdsvc-ct's host.v1 (with listenOptions.connectTimeout), bind, run host.
    let host_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("host enrolment succeeds");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host mTLS client builds");
    host.authenticate().await.expect("host authenticate");
    let services = host
        .list_services_with_config_types(&["host.v1".to_string()])
        .await
        .expect("list services with host.v1");
    let svc = services
        .iter()
        .find(|s| s.name == SERVICE)
        .unwrap_or_else(|| panic!("{SERVICE} visible to host"));
    let host_v1 = svc
        .host_v1_config()
        .expect(
            "fwdsvc-ct host.v1 parses (if connectTimeout served as a NUMBER, this Err → re-slice)",
        )
        .expect("fwdsvc-ct has a host.v1 config");
    // LOAD-BEARING wire-shape assertion: the controller serves connectTimeout as the STRING "10s" our
    // serde parses. A number-on-the-wire would already have failed `host_v1_config()` above.
    let lo = host_v1
        .listen_options
        .as_ref()
        .expect("fwdsvc-ct host.v1 has listenOptions");
    assert_eq!(
        lo.connect_timeout.as_deref(),
        Some("10s"),
        "the controller round-trips connectTimeout as the string '10s'"
    );
    let binding = host.bind(SERVICE).await.expect("bind(fwdsvc-ct) succeeds");
    println!("host bound '{SERVICE}': conn_id={}", binding.conn_id());

    // Dialer: enrol, auth.
    let dialer_jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).unwrap();
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("dialer enrolment succeeds");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer mTLS client builds");
    dialer.authenticate().await.expect("dialer authenticate");

    // appData carries dst_ip/dst_port (the echo); the host resolves the target and dials with the
    // configured 10s timeout (the echo is reachable, so the dial succeeds well within it).
    let app_data = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        None,
    );
    let payload = payload.to_vec();
    tokio::task::LocalSet::new()
        .run_until(async move {
            let host_loop = tokio::task::spawn_local(run_tcp_host_forwarding(binding, host_v1));

            let mut dconn = dialer
                .connect_with_appdata(SERVICE, Duration::from_secs(15), Some(&app_data))
                .await
                .expect("dialer connect_with_appdata(fwdsvc-ct)");
            dconn.write(&payload).await.expect("dialer writes");
            let got = tokio::time::timeout(Duration::from_secs(20), dconn.read())
                .await
                .expect("dialer read did not time out")
                .expect("dialer reads echo");
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "round-trip THROUGH run_tcp_host_forwarding with a connectTimeout-configured host dial"
            );
            dconn.close().await.ok();
            host_loop.abort();
        })
        .await;
    echo.abort();
    println!(
        "tunneler T4b-2c OK live: connectTimeout '10s' round-tripped as a string + resolved the host dial timeout; round-trip OK"
    );
}

// Tunneler T5 (svc-poller) slice 1: a happy-path live of `poll_services`. Per the live-validation rule
// `poll_services` reuses the ALREADY-VALIDATED `list_services` wire (no NEW wire — the
// `IsServiceListUpdateAvailable` update-check is deferred to T5-2), so the diff/event/cache LOGIC is
// covered by unit/wiremock; this live test only confirms the wrapper end-to-end: a freshly enrolled
// identity's first poll reports its visible services as `Added` (firing a registered listener), and an
// immediate second poll reports NOTHING (the cache persisted → idempotent).
#[tokio::test]
#[ignore = "requires a live OpenZiti controller + online router + hosted testsvc/testsvc-noenc; tunneler T5"]
async fn enrol_then_poll_services_detects_initial_set() {
    use noa_sdk::edge::services::ServiceEvent;
    use std::sync::{Arc, Mutex};

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // A listener records each event by label, proving the fan-out fires live.
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let _id = client.add_service_listener(Arc::new(move |ev: &ServiceEvent| {
        let label = match ev {
            ServiceEvent::Added(s) => format!("+{}", s.name),
            ServiceEvent::Changed(s) => format!("~{}", s.name),
            ServiceEvent::Removed(s) => format!("-{}", s.name),
        };
        seen_cb.lock().unwrap().push(label);
    }));

    // First poll: every visible service is Added (the cache started empty).
    let first = client.poll_services(&[]).await.expect("first poll");
    assert!(
        !first.is_empty(),
        "a fresh identity should see at least one Dial-able service (testsvc/testsvc-noenc)"
    );
    assert!(
        first.iter().all(|e| matches!(e, ServiceEvent::Added(_))),
        "first poll must be all Added, got {first:?}"
    );
    let names: Vec<String> = first
        .iter()
        .map(|e| match e {
            ServiceEvent::Added(s) | ServiceEvent::Changed(s) | ServiceEvent::Removed(s) => {
                s.name.clone()
            }
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "testsvc" || n == "testsvc-noenc"),
        "expected a known hosted service in the initial set, got {names:?}"
    );
    // The listener saw exactly the first-poll events.
    assert_eq!(
        seen.lock().unwrap().len(),
        first.len(),
        "listener fan-out fired once per event"
    );

    // Second poll IMMEDIATELY after: the set is unchanged → no events (the cache persisted across
    // polls). This is the load-bearing live signal that the diff/cache wiring works end-to-end.
    let second = client.poll_services(&[]).await.expect("second poll");
    assert!(
        second.is_empty(),
        "an immediate re-poll of an unchanged service set must emit nothing, got {second:?}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        first.len(),
        "no new listener calls on an unchanged re-poll"
    );

    println!(
        "tunneler T5 OK live: poll_services reported {} services Added then a clean re-poll ({names:?})",
        first.len()
    );
}

// Tunneler T5-2a: a happy-path live of the NEW `/current-api-session/service-updates` wire + the
// update-check-gated `poll_services_if_changed`. This wire IS new → it earns a live test
// (live-validation rule: new wire needs a live test); the timer (T5-2b) and the diff logic stay unit/wiremock. The test is
// NON-VACUOUS about the load-bearing claim (the instant comparison): after a conditional poll stores
// the controller's current `lastChangeAt`, a fresh `is_service_list_update_available()` must return
// `false` (the stored instant equals the controller's, instant-wise) — a broken parse/compare would
// return `true`. That single assertion validates the new wire AND empirically de-risks the
// `unix_timestamp_nanos` instant comparison against a REAL controller timestamp.
#[tokio::test]
#[ignore = "requires a live OpenZiti controller + online router + hosted testsvc/testsvc-noenc; tunneler T5-2a"]
async fn enrol_then_service_updates_gates_refresh() {
    use noa_sdk::edge::services::ServiceEvent;

    let jwt = std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).unwrap();
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // (1) Before any check has stored an instant, an update IS available (the oracle's
    // `lastServiceUpdate == nil` arm).
    assert!(
        client
            .is_service_list_update_available()
            .await
            .expect("service-updates GET (1) succeeds"),
        "with no stored instant, an update must be reported available"
    );

    // (2) The first conditional poll → check-needed → fetch → every visible service Added; it stores
    // the controller's current lastChangeAt instant.
    let first = client
        .poll_services_if_changed(&[])
        .await
        .expect("first conditional poll");
    assert!(
        !first.is_empty() && first.iter().all(|e| matches!(e, ServiceEvent::Added(_))),
        "first conditional poll must fetch and report all Added, got {first:?}"
    );
    let names: Vec<String> = first
        .iter()
        .map(|e| match e {
            ServiceEvent::Added(s) | ServiceEvent::Changed(s) | ServiceEvent::Removed(s) => {
                s.name.clone()
            }
        })
        .collect();
    assert!(
        names.iter().any(|n| n == "testsvc" || n == "testsvc-noenc"),
        "expected a known hosted service in the initial set, got {names:?}"
    );

    // (3) LOAD-BEARING: with the controller's instant now stored, a fresh pure check returns `false`
    // (no update) — proving the wire parsed a real `lastChangeAt` AND the instant comparison holds
    // against the live controller. A quiet rig keeps lastChangeAt stable between (2) and (3).
    assert!(
        !client
            .is_service_list_update_available()
            .await
            .expect("service-updates GET (3) succeeds"),
        "after storing the current instant, the pure check must report NO update on a quiet rig"
    );

    // (4) The gate skips the fetch on the second conditional poll → no events.
    let second = client
        .poll_services_if_changed(&[])
        .await
        .expect("second conditional poll");
    assert!(
        second.is_empty(),
        "an unchanged conditional re-poll must emit nothing (the gate skipped the fetch), got {second:?}"
    );

    println!(
        "tunneler T5-2a OK live: /service-updates gated the refresh — {} services on first poll, \
         then check=false + a no-op re-poll ({names:?})",
        first.len()
    );
}
