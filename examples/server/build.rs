use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let server_example_protos_file: &str = "proto/server_example.proto";

    // ONLY compile server_example.proto
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("server_example_service.bin"))
        .out_dir("./src")
        .compile_protos(
            &[server_example_protos_file], 
            &["proto"]
        )
        .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));

    println!("cargo:rerun-if-changed={}", server_example_protos_file);
}