#![no_main]

use arbitrary::Arbitrary;
use bytes::BufMut;
use commonware_runtime::{deterministic, Blob, Runner, Storage};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::U64;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    blob_data: Vec<u8>,
    corrupt_checksum: bool,
    truncate_at: Option<usize>,
    use_left_blob: bool,
}

fn create_malformed_blob(input: &FuzzInput) -> Vec<u8> {
    if input.blob_data.is_empty() {
        return Vec::new();
    }
    
    let mut blob = Vec::new();
    
    blob.put_u64(1);
    
    let mut i = 0;
    while i + 16 <= input.blob_data.len() {
        let key_bytes = &input.blob_data[i..i + 8];
        blob.put_slice(key_bytes);
        
        if i + 12 <= input.blob_data.len() {
            let size = u32::from_be_bytes([
                input.blob_data[i + 8],
                input.blob_data[i + 9],
                input.blob_data[i + 10],
                input.blob_data[i + 11],
            ]) as usize;
            
            let encoded_size = size.saturating_add(100000);
            blob.put_u32(encoded_size as u32);
            
            let actual_data_start = i + 12;
            let actual_data_end = (actual_data_start + 100).min(input.blob_data.len());
            if actual_data_start < actual_data_end {
                blob.put_slice(&input.blob_data[actual_data_start..actual_data_end]);
            } else {
                blob.put_slice(&[0u8; 4]);
            }
        }
        
        i += 16;
    }
    
    let checksum_index = blob.len();
    let checksum = if input.corrupt_checksum {
        0xDEADBEEF
    } else {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&blob[..checksum_index]);
        hasher.finalize()
    };
    blob.put_u32(checksum);
    
    if let Some(truncate_at) = input.truncate_at {
        blob.truncate(truncate_at.min(blob.len()));
    }
    
    blob
}

fuzz_target!(|input: FuzzInput| {
    let runner = deterministic::Runner::default();
    
    runner.start(|context| async move {
        let malformed_blob = create_malformed_blob(&input);
        
        let blob_name = if input.use_left_blob { b"left" as &[u8] } else { b"right" as &[u8] };
        let other_name = if input.use_left_blob { b"right" as &[u8] } else { b"left" as &[u8] };
        
        let (target_blob, _) = context.open("fuzz_test", blob_name).await.unwrap();
        if !malformed_blob.is_empty() {
            target_blob.write_at(malformed_blob, 0).await.unwrap();
            target_blob.sync().await.unwrap();
        }
        
        let (other_blob, _) = context.open("fuzz_test", other_name).await.unwrap();
        let empty_blob = vec![0u8; 8 + 4];
        other_blob.write_at(empty_blob, 0).await.unwrap(); 
        other_blob.sync().await.unwrap();
        
        let cfg = Config {
            partition: "fuzz_test".to_string(),
            codec_config: ((0..).into(), ()),
        };
        
        let _ = Metadata::<_, U64, Vec<u8>>::init(context, cfg).await;
    });
});