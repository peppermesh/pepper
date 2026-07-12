// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use pepper_dag::{TraversalLimits, builtin_registry};
use pepper_types::{
    CODEC_DIR_MANIFEST, CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_RAW,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let codec = match selector % 4 {
        0 => CODEC_RAW,
        1 => CODEC_OBJECT_MANIFEST,
        2 => CODEC_ERASURE_MANIFEST,
        _ => CODEC_DIR_MANIFEST,
    };
    let limits = TraversalLimits {
        max_payload_bytes: 1024 * 1024,
        max_links_per_block: 4096,
        ..TraversalLimits::default()
    };
    let _ = builtin_registry().links(codec, payload, &limits);
});
