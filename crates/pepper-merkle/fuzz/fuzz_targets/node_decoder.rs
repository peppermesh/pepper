// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use pepper_dag::{DagCodecHandler, TraversalLimits};
use pepper_merkle::MerkleNodeCodecHandler;

fuzz_target!(|data: &[u8]| {
    let _ = MerkleNodeCodecHandler.links(data, &TraversalLimits::default());
});
