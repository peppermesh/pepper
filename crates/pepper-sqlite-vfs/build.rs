// SPDX-License-Identifier: Apache-2.0

fn main() {
    let include = std::env::var("DEP_SQLITE3_INCLUDE")
        .expect("libsqlite3-sys must expose its bundled SQLite include directory");
    cc::Build::new()
        .file("src/batch_spike.c")
        .file("src/pepper_vfs.c")
        .include(include)
        .warnings(true)
        .extra_warnings(true)
        .compile("pepper_sqlite_batch_spike");
    println!("cargo:rerun-if-changed=src/batch_spike.c");
    println!("cargo:rerun-if-changed=src/pepper_vfs.c");
}
