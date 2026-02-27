//! `obsidianq unmount` — signal a running mount to stop.

use anyhow::{bail, Context, Result};
use clap::Args;

use obsidianq_fs::unmount_container;

#[derive(Args)]
pub struct UnmountArgs {
    /// Drive letter to unmount (e.g. Z or Z:)
    #[arg(long)]
    pub drive: String,
}

pub fn run(args: UnmountArgs) -> Result<()> {
    let dl = args.drive.trim_end_matches(':').chars().next()
        .context("--drive must be a letter such as Z or Z:")?
        .to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        bail!("invalid drive letter '{dl}'");
    }
    unmount_container(dl).map_err(|e| anyhow::anyhow!("{e}"))
}
