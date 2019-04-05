[![Build Status](https://travis-ci.com/Team-Hycon/hycon-rust.svg?branch=master)](https://travis-ci.com/Team-Hycon/hycon-rust)
# TOKIO Networking Experiment
Evaluating Tokio for use in the rust implementation of the Hycon-core client

## Project Details
1. Establish Basic Tokio Network using protocol buffers
2. Confirm compatability with existing network
3. Evaluate concurrently with [cap'n proto experiment](https://github.com/elniallo/capnproto-experiment)

## Resources
Used [tokio chat example](https://github.com/tokio-rs/tokio-core/blob/master/examples/chat.rs) as a reference.

## Usage
To run a client:
```
cargo run server $HOST:$PORT
```
Testing and Benchmarks(using Criterion) also included via:
```
cargo test
```
and
```
cargo bench
```

## Documentation
 - [Hycon Rest API](https:://docs.hycon.io)
 - [Rust Implementation Docs](https:://team-hycon.github.io/hycon-rust/) 
