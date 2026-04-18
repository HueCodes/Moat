//! Benchmarks for Moat's hot-path crypto.
//!
//! Measures:
//! - token signing (Ed25519 sign over canonical bytes + SHA-256 prehash)
//! - token signature verification (what the PEP does per message)
//! - message signing (AuthenticatedMessage::create)
//! - message signature verification
//! - action evaluation on a capability token (resource + action check)

use chrono::{Duration, Utc};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use moat_core::{
    AgentKeypair, AuthenticatedMessage, CapabilityToken, PolicyBinding, ScopeEntry,
};

fn sample_signed_root(kp: &AgentKeypair) -> CapabilityToken {
    let mut tok = CapabilityToken::root(kp.id(), kp.id(), Utc::now() + Duration::hours(1));
    tok.allowed = vec![ScopeEntry {
        resource: "tool://analyze".into(),
        actions: vec!["read".into(), "execute".into()],
    }];
    tok.sign(kp);
    tok
}

fn bench_token_sign(c: &mut Criterion) {
    let kp = AgentKeypair::generate("issuer").unwrap();
    let mut group = c.benchmark_group("token");
    group.throughput(Throughput::Elements(1));
    group.bench_function("sign", |b| {
        b.iter(|| {
            let mut tok =
                CapabilityToken::root(kp.id(), kp.id(), Utc::now() + Duration::hours(1));
            tok.allowed = vec![ScopeEntry {
                resource: "tool://analyze".into(),
                actions: vec!["read".into()],
            }];
            tok.sign(black_box(&kp));
            black_box(tok);
        });
    });
    group.finish();
}

fn bench_token_verify(c: &mut Criterion) {
    let kp = AgentKeypair::generate("issuer").unwrap();
    let tok = sample_signed_root(&kp);
    let mut group = c.benchmark_group("token");
    group.throughput(Throughput::Elements(1));
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            tok.verify_signature(black_box(&kp.identity)).unwrap();
        });
    });
    group.finish();
}

fn bench_token_action_check(c: &mut Criterion) {
    let kp = AgentKeypair::generate("issuer").unwrap();
    let tok = sample_signed_root(&kp);
    let mut group = c.benchmark_group("token");
    group.throughput(Throughput::Elements(1));
    group.bench_function("is_action_allowed", |b| {
        b.iter(|| {
            tok.is_action_allowed(black_box("tool://analyze"), black_box("read"))
                .unwrap();
        });
    });
    group.finish();
}

fn bench_message_create(c: &mut Criterion) {
    let sender = AgentKeypair::generate("sender").unwrap();
    let recipient = AgentKeypair::generate("recipient").unwrap();
    let tok = sample_signed_root(&sender);
    let policy = PolicyBinding::new("bench-v1", b"bench policy");
    let payload = vec![0u8; 256]; // typical small message
    let mut group = c.benchmark_group("message");
    group.throughput(Throughput::Elements(1));
    group.bench_function("create_256b", |b| {
        let mut seq: u64 = 1;
        b.iter(|| {
            seq += 1;
            let msg = AuthenticatedMessage::create(
                &sender,
                recipient.id(),
                payload.clone(),
                tok.clone(),
                vec![],
                policy.clone(),
                seq,
            )
            .unwrap();
            black_box(msg);
        });
    });
    group.finish();
}

fn bench_message_verify(c: &mut Criterion) {
    let sender = AgentKeypair::generate("sender").unwrap();
    let recipient = AgentKeypair::generate("recipient").unwrap();
    let tok = sample_signed_root(&sender);
    let policy = PolicyBinding::new("bench-v1", b"bench policy");
    let payload = vec![0u8; 256];
    let msg = AuthenticatedMessage::create(
        &sender,
        recipient.id(),
        payload,
        tok,
        vec![],
        policy,
        1,
    )
    .unwrap();
    let mut group = c.benchmark_group("message");
    group.throughput(Throughput::Elements(1));
    group.bench_function("verify_signature_256b", |b| {
        b.iter(|| {
            msg.verify_signature(black_box(&sender.identity)).unwrap();
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_token_sign,
    bench_token_verify,
    bench_token_action_check,
    bench_message_create,
    bench_message_verify,
);
criterion_main!(benches);
