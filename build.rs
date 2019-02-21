extern crate protoc_rust_no_elision;

fn main() {
    println!("Building...");
    protoc_rust_no_elision::run(protoc_rust_no_elision::Args {
        out_dir: "src/serialization",
        input: &[
            "src/proto/block.proto",
            "src/proto/blockHeader.proto",
            "src/proto/network.proto",
            "src/proto/peer.proto",
            "src/proto/state.proto",
            "src/proto/tx.proto",
        ],
        includes: &["src/proto/"],
        customize: protoc_rust_no_elision::Customize {
            ..Default::default()
        },
    }).expect("protoc");
}
