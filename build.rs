fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/compact_formats.proto", "proto/service.proto"],
            &["proto/"],
        )?;
    Ok(())
}
