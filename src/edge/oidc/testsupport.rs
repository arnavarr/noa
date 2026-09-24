//! Helpers compartidos por los módulos de test de `oidc` (F6 tramo 4: movidos verbatim del monolito de
//! `edge/oidc`).

use super::pkce::b64url_nopad;

pub(super) fn make_jwt(payload_json: &str) -> String {
    let h = b64url_nopad(b"{\"alg\":\"RS256\"}");
    let p = b64url_nopad(payload_json.as_bytes());
    format!("{h}.{p}.sig")
}

/// Mount the authorize + callback + token mocks shared by every TOTP test (the legs that bracket
/// the TOTP submit). The login + totp mocks are mounted per-test (their responses are what varies).
/// Returns the (server, captured_state, captured_nonce). The token responder echoes the nonce so
/// the unconditional nonce check passes on the success path.
pub(super) async fn mount_oidc_brackets(
    server: &wiremock::MockServer,
) -> (
    std::sync::Arc<std::sync::Mutex<String>>,
    std::sync::Arc<std::sync::Mutex<String>>,
) {
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, Request, Respond, ResponseTemplate};

    struct AuthorizeResponder {
        state: StdArc<StdMutex<String>>,
        nonce: StdArc<StdMutex<String>>,
    }
    impl Respond for AuthorizeResponder {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let url = req.url.clone();
            let pick = |key: &str| {
                url.query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            *self.state.lock().unwrap() = pick("state");
            *self.nonce.lock().unwrap() = pick("nonce");
            ResponseTemplate::new(302)
                .insert_header("Location", "/oidc/login/cert?authRequestID=AR1")
        }
    }
    struct CallbackResponder(StdArc<StdMutex<String>>);
    impl Respond for CallbackResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let state = self.0.lock().unwrap().clone();
            ResponseTemplate::new(302).insert_header(
                "Location",
                format!("http://localhost:8080/auth/callback?code=CODE1&state={state}").as_str(),
            )
        }
    }
    struct TokenResponder(StdArc<StdMutex<String>>);
    impl Respond for TokenResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let nonce = self.0.lock().unwrap().clone();
            let id_token = make_jwt(&format!(r#"{{"name":"mfauser","nonce":"{nonce}"}}"#));
            ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"access_token":"ey.MFAACCESS","refresh_token":"ey.MFAREFRESH","expires_in":1800,"id_token":"{id_token}","token_type":"Bearer"}}"#
            ))
        }
    }

    let state: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));
    let nonce: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(AuthorizeResponder {
            state: state.clone(),
            nonce: nonce.clone(),
        })
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oidc/authorize/callback"))
        .respond_with(CallbackResponder(state.clone()))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(TokenResponder(nonce.clone()))
        .mount(server)
        .await;
    (state, nonce)
}
