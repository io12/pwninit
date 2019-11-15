set -ex

cargo build --release
cargo test --release
strip target/release/pwninit
