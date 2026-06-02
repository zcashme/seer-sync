// Compiles the lightwalletd protos into Rust under OUT_DIR; src/proto.rs
// includes the result.
//
// The generated blob has two parts: prost *message* types (CompactBlock, etc.)
// and the tonic gRPC *client* (CompactTxStreamerClient). The messages are core
// (the sans-IO scanner takes CompactBlock); the client only matters when we
// actually talk to a server. So we emit the client only when the `lwd` feature
// is on — keeping the default-features-off build free of any tonic reference.
//
// `CARGO_FEATURE_LWD` is Cargo's own signal: it sets CARGO_FEATURE_<NAME>=1 for
// every enabled feature. A build script can't see `#[cfg]` (it runs before the
// crate compiles), so this env var is the only channel.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lwd = std::env::var_os("CARGO_FEATURE_LWD").is_some();
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(lwd)
        .compile_protos(
            &["proto/compact_formats.proto", "proto/service.proto"],
            &["proto/"],
        )?;
    Ok(())
}
