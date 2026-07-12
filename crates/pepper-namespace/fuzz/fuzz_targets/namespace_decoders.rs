// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use pepper_dag::{DagCodecHandler, TraversalLimits};
use pepper_namespace::{
    NamespaceCheckpointCodecHandler, NamespaceCommitCodecHandler, NamespaceDescriptorCodecHandler,
    decode_command_envelope,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => {
            let _ = NamespaceDescriptorCodecHandler.links(payload, &TraversalLimits::default());
        }
        1 => {
            let _ = NamespaceCheckpointCodecHandler.links(payload, &TraversalLimits::default());
        }
        2 => {
            let _ = NamespaceCommitCodecHandler.links(payload, &TraversalLimits::default());
        }
        _ => {
            let _ = decode_command_envelope(payload);
        }
    }
});
