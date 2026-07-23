// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use pepper_dag::{DagCodecHandler, TraversalLimits};
use pepper_sqlite::{
    LocalFrame, LocalProtocolLimits, PepperDatabaseUri,
    format::{SqliteDatabaseCodecHandler, SqlitePageTableCodecHandler, SqliteSnapshotCodecHandler},
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    match selector % 5 {
        0 => {
            let _ = SqliteDatabaseCodecHandler.links(payload, &TraversalLimits::default());
        }
        1 => {
            let _ = SqliteSnapshotCodecHandler.links(payload, &TraversalLimits::default());
        }
        2 => {
            let _ = SqlitePageTableCodecHandler.links(payload, &TraversalLimits::default());
        }
        3 => {
            let _ = LocalFrame::decode(payload, LocalProtocolLimits::default());
        }
        _ => {
            if let Ok(uri) = std::str::from_utf8(payload) {
                let _ = PepperDatabaseUri::parse(uri);
            }
        }
    }
});
