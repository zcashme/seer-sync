fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["proto/compact_formats.proto", "proto/service.proto"],
            &["proto/"],
        )?;

    // Server stubs for the in-crate mock lightwalletd; only `cfg(test)` includes them.
    let server_out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("test-server");
    std::fs::create_dir_all(&server_out)?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .generate_default_stubs(true)
        .out_dir(server_out)
        .compile_protos(
            &["proto/compact_formats.proto", "proto/service.proto"],
            &["proto/"],
        )?;
    Ok(())
}
