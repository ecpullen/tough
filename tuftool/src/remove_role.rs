// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};
use crate::source::parse_key_source;
use snafu::ResultExt;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::PathBuf;
use structopt::StructOpt;
use tempfile::tempdir;
use tough::editor::RepositoryEditor;
use tough::http::HttpTransport;
use tough::key_source::KeySource;
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository};
use url::Url;

#[derive(Debug, StructOpt)]
pub(crate) struct RemoveRoleArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// Role to remove
    #[structopt(long = "delegatee")]
    delegatee: String,

    /// Version of targets.json file
    #[structopt(short = "v", long = "version")]
    version: Option<NonZeroU64>,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// Threshold of signatures to sign delegatee
    #[structopt(short = "t", long = "threshold")]
    threshold: Option<NonZeroU64>,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,

    /// Determine if the role should be removed even if it's not a direct delegatee
    #[structopt(long = "recursive")]
    recursive: bool,

    /// Determins if entire repo should be signed
    #[structopt(long = "sign-all")]
    sign_all: bool,
}

impl RemoveRoleArgs {
    pub(crate) fn run(&self, role: &str) -> Result<()> {
        // load the repo
        let datastore = tempdir().context(error::TempDir)?;
        // We don't do anything with targets so we will use metadata url
        let settings = tough::Settings {
            root: File::open(&self.root).unwrap(),
            datastore: &datastore.path(),
            metadata_base_url: self.metadata_base_url.as_str(),
            targets_base_url: self.metadata_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        };

        // Load the `Repository` into the `RepositoryEditor`
        // Loading a `Repository` with different `Transport`s results in
        // different types. This is why we can't assign the `Repository`
        // to a variable with the if statement.
        let mut editor = if self.metadata_base_url.scheme() == "file" {
            let repository =
                Repository::load(&FilesystemTransport, settings).context(error::RepoLoad)?;
            RepositoryEditor::from_repo(&self.root, repository)
        } else {
            let transport = HttpTransport::new();
            let repository = Repository::load(&transport, settings).context(error::RepoLoad)?;
            RepositoryEditor::from_repo(&self.root, repository)
        }
        .context(error::EditorFromRepo { path: &self.root })?;

        // remove `delegatee`
        editor
            .remove_role(&self.delegatee, role, self.recursive)
            .context(error::RemoveRole {
                role: self.delegatee.clone(),
                from: role,
            })?;

        // if sign-all is included sign and write entire repo
        if self.sign_all {
            let signed_repo = editor.sign(&self.keys).context(error::SignRepo)?;
            let metadata_dir = &self.outdir.join("metadata");
            signed_repo.write(metadata_dir).context(error::WriteRepo {
                directory: metadata_dir,
            })?;

            return Ok(());
        }

        // sign the role
        let new_role = editor
            .sign_roles(&self.keys, [role].to_vec())
            .context(error::SignRoles {
                roles: [role.to_string()].to_vec(),
            })?
            .remove(role)
            .ok_or_else(|| error::Error::SignRolesRemove {
                roles: [role.to_string()].to_vec(),
            })?;

        // write the role to outdir
        let metadata_destination_out = &self.outdir.join("metadata");
        new_role
            .write_del_role(&metadata_destination_out, false, role)
            .context(error::WriteRoles {
                roles: [role.to_string()].to_vec(),
            })?;

        Ok(())
    }
}
