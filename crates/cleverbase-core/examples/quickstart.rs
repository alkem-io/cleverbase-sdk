//! Minimal usage example for the Cleverbase SDK core.
//!
//! Run with: `cargo run -p cleverbase-core --example quickstart`
//!
//! Shows the sans-IO loop shape: `begin` returns the first effect (here, the authorization
//! redirect). A real integrator then performs each emitted HTTP effect / redirect and calls
//! `resume` with the result until it gets `Step::Done { signed, evidence }`.

// A runnable usage example: printing to stdout and `expect`-ing on a hard-coded happy path is the
// point of the demo, so the library's strict no-print / no-expect restriction lints are relaxed
// here only.
#![allow(clippy::print_stdout, clippy::expect_used)]

use cleverbase_core::{
    begin, ConformanceLevel, CscApi, Environment, HostContext, Secret, SigningRequest, Step,
    TrustServiceConfiguration,
};

fn main() {
    let request = SigningRequest {
        document: b"%PDF-1.7\n... your PDF bytes ...".to_vec(),
        conformance_level: ConformanceLevel::BB,
        expected_signer: None,
        appearance: None,
        signature_meta: None,
    };

    let config = TrustServiceConfiguration {
        environment: Environment::Acceptance,
        csc_api: CscApi::V1Rsa,
        client_id: "your-client-id".into(),
        client_secret: Secret::new("your-client-secret"),
        redirect_uri: "https://your-app.example/callback".into(),
        tsa: None,
    };

    // The core is sans-IO and deterministic: the host supplies the clock and entropy.
    let ctx = HostContext {
        now_unix: 1_700_000_000,
        entropy: vec![0u8; 16],
    };

    let (handle, step) = begin(request, config, ctx).expect("begin signing");
    match step {
        Step::Redirect(r) => {
            println!("1. Send the signer's browser to:\n   {}", r.url);
            println!(
                "2. Persist the session handle (phase: {:?}) server-side until the signer returns.",
                handle.phase
            );
            println!("3. On return, call `resume` with the OAuth code+state, then perform each");
            println!(
                "   emitted HTTP effect and resume until you get Step::Done {{ signed, .. }}."
            );
        }
        other => println!("unexpected first step: {other:?}"),
    }
}
