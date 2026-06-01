// Compiles the lightwalletd protos into Rust under OUT_DIR; src/proto.rs
// includes the result. We generate the gRPC *client* only (build_server(false)):
// seer-sync calls a lightwalletd server, it doesn't implement one.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/compact_formats.proto", "proto/service.proto"],
            &["proto/"],
        )?;
    Ok(())
}
