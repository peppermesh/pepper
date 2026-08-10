// SPDX-License-Identifier: Apache-2.0

mod parse;
mod report;
mod run;
mod schema;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "pepper-parity")]
#[command(about = "Matched-guarantee performance parity harness: Pepper vs best-of-breed")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a suite definition and print its expanded cell matrix.
    Validate {
        #[arg(long)]
        suite: PathBuf,
    },
    /// Bring up targets, run every cell, tear down, and emit the parity report.
    Run {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        output_directory: PathBuf,
        /// Restrict execution to the named targets (repeatable, comma separated).
        #[arg(long, value_delimiter = ',')]
        targets: Option<Vec<String>>,
        /// Leave target topologies running after measurement.
        #[arg(long, default_value_t = false)]
        keep_targets_up: bool,
    },
    /// Recompute the parity report from an existing cell-records.json.
    Report {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        records: PathBuf,
        /// Optional path for the Markdown report; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Validate { suite } => {
            let suite = schema::Suite::load(&suite)?;
            println!(
                "suite {:?} ({}) is valid: {} targets, {} cells, {} repetitions",
                suite.title,
                suite.api,
                suite.targets.len(),
                suite.cells().len(),
                suite.workload.repetitions
            );
            for target in &suite.targets {
                println!(
                    "  target {} ({:?}, profile {})",
                    target.name, target.role, target.profile
                );
            }
            for cell in suite.cells() {
                println!("  cell {}", cell.label());
            }
            Ok(())
        }
        Command::Run {
            suite,
            output_directory,
            targets,
            keep_targets_up,
        } => {
            run::run(run::RunOptions {
                suite_path: suite,
                output_directory,
                targets,
                keep_targets_up,
            })
            .await
        }
        Command::Report {
            suite,
            records,
            output,
        } => {
            let suite = schema::Suite::load(&suite)?;
            let records_text = std::fs::read_to_string(&records)
                .with_context(|| format!("failed to read {}", records.display()))?;
            let records: Vec<report::CellRecord> =
                serde_json::from_str(&records_text).context("failed to parse cell records JSON")?;
            let parity = report::compute(&suite, &records)?;
            let markdown = report::render_markdown(&parity);
            match output {
                Some(path) => {
                    std::fs::write(&path, &markdown)
                        .with_context(|| format!("failed to write {}", path.display()))?;
                    println!("wrote {}", path.display());
                }
                None => println!("{markdown}"),
            }
            if !parity.passed {
                anyhow::bail!("parity gate failed: {}", parity.summary);
            }
            Ok(())
        }
    }
}
