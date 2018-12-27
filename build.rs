extern crate protoc_rust_no_elision;

fn main() {
    println!("Building...");
    protoc_rust_no_elision::run(protoc_rust_no_elision::Args {
        out_dir: "src/serialization",
        input: &[
            "src/proto/protocol.proto",
        ],
        includes: &["src/proto/"],
        customize: protoc_rust_no_elision::Customize {
            ..Default::default()
        },
    }).expect("protoc");
}