// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
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
pub(crate) struct AddKeyArgs {
    /// Key files to sign with
    #[structopt(short = "k", long = "key", required = true, parse(try_from_str = parse_key_source))]
    keys: Vec<Box<dyn KeySource>>,

    /// New keys to be used for role
    #[structopt(long = "new-key", required = true, parse(try_from_str = parse_key_source))]
    new_keys: Vec<Box<dyn KeySource>>,

    /// Expiration of new role file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[structopt(short = "e", long = "expires", parse(try_from_str = parse_datetime))]
    expires: Option<DateTime<Utc>>,

    /// Version of role file
    #[structopt(short = "v", long = "version")]
    version: Option<NonZeroU64>,

    /// Path to root.json file for the repository
    #[structopt(short = "r", long = "root")]
    root: PathBuf,

    /// TUF repository metadata base URL
    #[structopt(short = "m", long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the repository will be written
    #[structopt(short = "o", long = "outdir")]
    outdir: PathBuf,
}

impl AddKeyArgs {
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

        // add keys to `role`
        editor
            .add_key_to_delegatee(role, &self.new_keys)
            .context(error::AddKey)?;

        // update the role
        editor
            .update_role(role, self.expires, self.version)
            .context(error::UpdateRole { role })?;

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
