fn main() {
    let proto = "../../core/server/gen/libcore.proto";
    println!("cargo:rerun-if-changed={proto}");
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    prost_build::compile_protos(&[proto], &["../../core/server/gen"]).unwrap();
}
