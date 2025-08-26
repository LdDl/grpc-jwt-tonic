use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let jwt_protos_file: &str = "protos/jwt.proto";

    // JWT proto files
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("jwt_service.bin"))
        .out_dir("./src")
        .compile_protos(&[jwt_protos_file], &["protos"])
        .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));

    println!("cargo:rerun-if-changed={}", jwt_protos_file);
}
