// SPDX-License-Identifier: Apache-2.0

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("failed to locate the vendored protoc binary");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(&["../../proto/pepper/v1/network.proto"], &["../../proto"])
        .expect("failed to compile Pepper network protobuf schema");
}
