// SPDX-License-Identifier: Apache-2.0

fn main() {
    prost_build::compile_protos(&["../../proto/pepper/v1/network.proto"], &["../../proto"])
        .expect("failed to compile Pepper network protobuf schema");
}
