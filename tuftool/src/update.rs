// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use snafu::ResultExt;
use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use structopt::StructOpt;
use tempfile::tempdir;
use tough::editor::RepositoryEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository, Transport};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct UpdateArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Version of snapshot.json file
    #[structopt(long = "snapshot-version")]
    snapshot_version: Option<NonZeroU64>,
    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "snapshot-expires", parse(try_from_str = parse_datetime))]
    snapshot_expires: Option<DateTime<Utc>>,

    /// Version of targets.json file
    #[structopt(long = "targets-version")]
    targets_version: Option<NonZeroU64>,
    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "targets-expires", parse(try_from_str = parse_datetime))]
    targets_expires: Option<DateTime<Utc>>,

    /// Version of timestamp.json file
    #[structopt(long = "timestamp-version")]
    timestamp_version: Option<NonZeroU64>,
    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(long = "timestamp-expires", parse(try_from_str = parse_datetime))]
    timestamp_expires: Option<DateTime<Utc>>,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Directory of targets
    #[structopt(short = "t", long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// Follow symbolic links in the given directory when adding targets
    #[structopt(short = "f", long = "follow")]
    follow: bool,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[structopt(short = "j", long = "jobs")]
    jobs: Option<NonZeroUsize>,

    /// The directory where the updated repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// Incoming metadata from delegatee
    #[structopt(short = "i", long = "incoming-metadata")]
    indir: Option<Url>,

    /// Role of incoming metadata
    #[structopt(long = "role")]
    role: Option<String>,

    /// Displays and overview of changes proposed by incoming
    #[structopt(subcommand)]
    command: Option<Command>,
}

impl UpdateArgs {
    pub(crate) fn run(&self) -> Result<()> {
        if let Some(Command::Changes(changes)) = &self.command {
            return changes.run(self);
        }
        // Create a temporary directory where the TUF client can store metadata
        let workdir = tempdir().context(error::TempDir)?;
        let settings = tough::Settings {
            root: File::open(&self.root).context(error::FileOpen { path: &self.root })?,
            datastore: workdir.path(),
            metadata_base_url: self.metadata_base_url.as_str(),
            // We never load any targets here so the real
            // `targets_base_url` isn't needed. `tough::Settings` requires
            // a value so we use `metadata_base_url` as a placeholder
            targets_base_url: self.metadata_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };
        let update = self.role.is_some() && self.indir.is_some();
        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        let mut editor = if self.metadata_base_url.scheme() == "file" {
            let mut repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            // If we were given incoming metadata we need to update it
            if update {
                repository
                    .load_update_delegated_role(
                        self.role.as_ref().unwrap(),
                        self.indir.as_ref().unwrap().as_str(),
                    )
                    .context(error::LoadMetadata)?;
            }
            RepositoryEditor::from_repo(&self.root, repository)
        } else {
            let transport = HttpTransport::new();
            let mut repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            // If we were given incoming metadata we need to update it
            if update {
                repository
                    .load_update_delegated_role(
                        self.role.as_ref().unwrap(),
                        self.indir.as_ref().unwrap().as_str(),
                    )
                    .context(error::LoadMetadata)?;
            }
            RepositoryEditor::from_repo(&self.root, repository)
        }
        .context(error::EditorFromRepo { path: &self.root })?;

        if let Some(targets_version) = self.targets_version {
            editor
                .targets_version(targets_version)
                .context(error::DelegationStructure)?;
        }
        if let Some(targets_expires) = self.targets_expires {
            editor
                .targets_expires(targets_expires)
                .context(error::DelegationStructure)?;
        }
        if let Some(snapshot_version) = self.snapshot_version {
            editor.snapshot_version(snapshot_version);
        }
        if let Some(snapshot_expires) = self.snapshot_expires {
            editor.snapshot_expires(snapshot_expires);
        }
        if let Some(timestamp_version) = self.timestamp_version {
            editor.timestamp_version(timestamp_version);
        }
        if let Some(timestamp_expires) = self.timestamp_expires {
            editor.timestamp_expires(timestamp_expires);
        }

        // If the "add-targets" argument was passed, build a list of targets
        // and add them to the repository. If a user specifies job count we
        // override the default, which is the number of cores.
        if let Some(ref targets_indir) = self.targets_indir {
            if let Some(jobs) = self.jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(usize::from(jobs))
                    .build_global()
                    .context(error::InitializeThreadPool)?;
            }

            let new_targets = build_targets(&targets_indir, self.follow)?;

            for (filename, target) in new_targets {
                editor
                    .add_target(&filename, target)
                    .context(error::DelegationStructure)?;
            }
        };

        // Sign the repo
        let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;

        // Symlink any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_repo
                .link_targets(&targets_indir, &targets_outdir)
                .context(error::LinkTargets {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_repo.write(metadata_dir).context(error::WriteRepo {
            directory: metadata_dir,
        })?;

        Ok(())
    }
}

#[derive(StructOpt, Debug)]
pub(crate) enum Command {
    /// List all changes running update will cause
    #[structopt(name = "changes")]
    Changes(ChangeArgs),
}

#[derive(Debug, StructOpt)]
pub(crate) struct ChangeArgs {
    /// Ignore changes to targets
    #[structopt(short = "t", long = "ignore-targets")]
    ignore_targets: bool,

    /// Ignore changes to targets
    #[structopt(short = "r", long = "ignore-roles")]
    ignore_roles: bool,

    /// Ignore expiration changes
    #[structopt(short = "e", long = "ignore-expiration")]
    ignore_expiration: bool,
}

impl ChangeArgs {
    pub(crate) fn run(&self, args: &UpdateArgs) -> Result<()> {
        println!(
            "Proposed Changes\n================================================================="
        );
        // Create a temporary directory where the TUF client can store metadata
        let workdir = tempdir().context(error::TempDir)?;
        let settings = tough::Settings {
            root: File::open(&args.root).context(error::FileOpen { path: &args.root })?,
            datastore: workdir.path(),
            metadata_base_url: args.metadata_base_url.as_str(),
            // We never load any targets here so the real
            // `targets_base_url` isn't needed. `tough::Settings` requires
            // a value so we use `metadata_base_url` as a placeholder
            targets_base_url: args.metadata_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };
        let update = args.role.is_some() && args.indir.is_some();
        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        if args.metadata_base_url.scheme() == "file" {
            let mut repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            self.repo_updates(&repository, args);
            // If we were given incoming metadata we need to update it
            if update && !self.ignore_roles {
                let old_role = repository
                    .delegated_role(args.role.as_ref().unwrap())
                    .ok_or_else(|| error::Error::DelegateNotFound {
                        role: args.role.as_ref().unwrap().clone(),
                    })?
                    .clone();

                repository
                    .load_update_delegated_role(
                        args.role.as_ref().unwrap(),
                        args.indir.as_ref().unwrap().as_str(),
                    )
                    .context(error::LoadMetadata)?;

                let new_role = repository
                    .delegated_role(&args.role.as_ref().unwrap())
                    .ok_or_else(|| error::Error::DelegateNotFound {
                        role: args.role.as_ref().unwrap().clone(),
                    })?;
                let role_diff = old_role
                    .diff_string(new_role)
                    .context(error::DelegationsStructure)?;
                println!("Update to {}: {}", args.role.as_ref().unwrap(), role_diff);
                println!("=================================================================");
            }
        } else {
            let transport = HttpTransport::new();
            let mut repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            self.repo_updates(&repository, args);
            // If we were given incoming metadata we need to update it
            if update && !self.ignore_roles {
                let old_role = repository
                    .delegated_role(args.role.as_ref().unwrap())
                    .ok_or_else(|| error::Error::DelegateNotFound {
                        role: args.role.as_ref().unwrap().clone(),
                    })?
                    .clone();

                repository
                    .load_update_delegated_role(
                        args.role.as_ref().unwrap(),
                        args.indir.as_ref().unwrap().as_str(),
                    )
                    .context(error::LoadMetadata)?;

                let new_role = repository
                    .delegated_role(&args.role.as_ref().unwrap())
                    .ok_or_else(|| error::Error::DelegateNotFound {
                        role: args.role.as_ref().unwrap().clone(),
                    })?;
                let role_diff = old_role
                    .diff_string(new_role)
                    .context(error::DelegationsStructure)?;
                println!("Update to {}: {}", args.role.as_ref().unwrap(), role_diff);
                println!("=================================================================");
            }
        }

        if !self.ignore_targets {
            // If the "add-targets" argument was passed, build a list of targets
            // and check their differences with the repo
            if let Some(ref targets_indir) = args.targets_indir {
                if let Some(jobs) = args.jobs {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(usize::from(jobs))
                        .build_global()
                        .context(error::InitializeThreadPool)?;
                }

                let new_targets = build_targets(&targets_indir, args.follow)?;
                if !new_targets.is_empty() {
                    println!("Updated Targets:");
                    for (filename, _) in new_targets {
                        println!("\t{}", filename);
                    }
                }
                println!("=================================================================");
            };
        }

        Ok(())
    }

    pub fn repo_updates<T>(&self, repository: &Repository<'_, T>, args: &UpdateArgs)
    where
        T: Transport,
    {
        let mut change = false;
        if let Some(snapshot_version) = args.snapshot_version {
            println!(
                "Update Snapshot from version {} to {}",
                repository.snapshot().signed.version,
                snapshot_version
            );
            change = true;
        }
        if !self.ignore_expiration {
            if let Some(snapshot_expires) = args.snapshot_expires {
                println!(
                    "Snapshot expiration bumped from {} to {}",
                    repository.snapshot().signed.expires,
                    snapshot_expires
                );
                change = true;
            }
        }
        if let Some(timestamp_version) = args.timestamp_version {
            println!(
                "Update Timestamp from version {} to {}",
                repository.timestamp().signed.version,
                timestamp_version
            );
            change = true;
        }
        if !self.ignore_expiration {
            if let Some(timestamp_expires) = args.timestamp_expires {
                println!(
                    "Timestamp expiration bumped from {} to {}",
                    repository.timestamp().signed.expires,
                    timestamp_expires
                );
                change = true;
            }
        }
        if let Some(targets_version) = args.targets_version {
            println!(
                "Update Targets from version {} to {}",
                repository.targets().signed.version,
                targets_version
            );
            change = true;
        }
        if !self.ignore_expiration {
            if let Some(targets_expires) = args.targets_expires {
                println!(
                    "Targets expiration bumped from {} to {}",
                    repository.targets().signed.expires,
                    targets_expires
                );
                change = true;
            }
        }
        if change {
            println!("=================================================================");
        }
    }
}
