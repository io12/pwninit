# This script takes care of testing your crate

set -ex

main() {
    cargo build --release
    cargo test --release
    strip target/release/pwninit
}
