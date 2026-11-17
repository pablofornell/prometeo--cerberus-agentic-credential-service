//! ssh-agent wire protocol: frame reader and request parser.
#![no_main]

use cerberus_ssh_agent::protocol::{
    MAX_FRAME_BYTES, Request, parse_request, read_frame,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The message parser takes a body directly.
    let _ = parse_request(data);
    // The frame reader takes a stream of frames: read until it ends or fails.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
        return;
    };
    runtime.block_on(async {
        let mut stream = data;
        while let Ok(Some(frame)) = read_frame(&mut stream).await {
            assert!(!frame.is_empty() && frame.len() <= MAX_FRAME_BYTES);
            if let Request::Sign { key_blob, data, .. } = parse_request(&frame) {
                assert!(key_blob.len() + data.len() <= frame.len());
            }
        }
    });
});
