// SPDX-License-Identifier: Apache-2.0

mod cache_fill;
mod loadgen;
mod matrix;
mod summarize;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "pepper-s3-throughput")]
#[command(about = "Pepper S3 throughput and bottleneck-isolation benchmark")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the clean-room synthetic S3 block-cache fill benchmark.
    RunCacheFill(cache_fill::CacheFillArgs),
    /// Flatten synthetic block-cache cell and per-query artifacts into CSV.
    SummarizeCacheFill(cache_fill::CacheFillSummaryArgs),
    /// Run one raw-storage or S3 load cell.
    Loadgen(loadgen::LoadgenArgs),
    /// Run or resume the Docker benchmark matrix.
    RunMatrix(matrix::MatrixArgs),
    /// Flatten completed cell artifacts into CSV.
    Summarize(summarize::SummarizeArgs),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::RunCacheFill(args) => cache_fill::run(args).await,
        Command::SummarizeCacheFill(args) => cache_fill::summarize(args),
        Command::Loadgen(args) => loadgen::run(args).await,
        Command::RunMatrix(args) => matrix::run(args).await,
        Command::Summarize(args) => summarize::run(args),
    }
}
