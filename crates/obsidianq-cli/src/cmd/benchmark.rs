//! Built-in CLI benchmark — quick comparison without Criterion overhead.
//! For detailed statistical benchmarks, run `cargo bench -p obsidianq-bench`.

use std::io::Cursor;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use rand::RngCore;

use obsidianq_core::{
    crypto::kdf::MasterKey,
    engine::{EncryptParams, DEFAULT_CHUNK_SIZE},
    format::{Mode, SuiteId},
};

#[derive(Args)]
pub struct BenchmarkArgs {
    /// Sizes to benchmark in MiB (comma-separated)
    #[arg(long, default_value = "1,100")]
    pub sizes: String,
}

pub fn run(args: BenchmarkArgs) -> Result<()> {
    let sizes_mib: Vec<usize> = args
        .sizes
        .split(',')
        .map(|s| s.trim().parse::<usize>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parse sizes: {e}"))?;

    let suites = [
        ("XChaCha20-Poly1305", SuiteId::XChaCha20Poly1305),
        ("AES-256-GCM       ", SuiteId::Aes256Gcm),
    ];

    let compress_opts = [(false, "no-compress"), (true, "compress   ")];

    println!(
        "\n{:<20} {:<8} {:<14} {:>12} {:>12}",
        "Suite", "Compress", "Size", "Enc MB/s", "Dec MB/s"
    );
    println!("{}", "─".repeat(72));

    let master_raw = {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b
    };
    let mut file_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut file_id);

    for size_mib in &sizes_mib {
        let size = size_mib * 1024 * 1024;
        let mut plaintext = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut plaintext);

        for (suite_name, suite) in &suites {
            for (compress, compress_name) in &compress_opts {
                let master_key = MasterKey::from_bytes(master_raw);
                let params = EncryptParams {
                    master_key,
                    kem_data: vec![0u8; 32], // dummy salt
                    mode:     Mode::Password,
                    suite:    *suite,
                    chunk_size: DEFAULT_CHUNK_SIZE,
                    compress: *compress,
                    file_id,
                };

                let mut enc_out = Cursor::new(Vec::with_capacity(size + 65536));
                let mut inp = Cursor::new(&plaintext);

                let enc_start = Instant::now();
                obsidianq_core::encrypt(params, &mut inp, &mut enc_out)?;
                let enc_elapsed = enc_start.elapsed();
                let enc_mbs = size as f64 / enc_elapsed.as_secs_f64() / 1_048_576.0;

                // Decrypt back.
                enc_out.set_position(0);
                let dec_key = MasterKey::from_bytes(master_raw);
                let mut dec_out = Cursor::new(Vec::with_capacity(size));
                let dec_start = Instant::now();
                obsidianq_core::decrypt(&dec_key, &mut enc_out, &mut dec_out)?;
                let dec_elapsed = dec_start.elapsed();
                let dec_mbs = size as f64 / dec_elapsed.as_secs_f64() / 1_048_576.0;

                println!(
                    "{:<20} {:<8} {:>8} MiB    {:>8.1}    {:>8.1}",
                    suite_name, compress_name, size_mib, enc_mbs, dec_mbs,
                );
            }
        }
    }

    println!();
    Ok(())
}
