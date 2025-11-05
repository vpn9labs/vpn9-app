fn main() {
    if let Ok(protoc_path) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", protoc_path);
    }
    println!("cargo:rerun-if-changed=proto/vpn9/daemon.proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile(&["proto/vpn9/daemon.proto"], &["proto"])
        .expect("failed to compile gRPC definitions");
}
