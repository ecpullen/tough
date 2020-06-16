// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{Duration, Utc};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroU64;
use std::path::PathBuf;
use tempfile::TempDir;
use test_utils::{dir_url, test_data};
use tough::editor::RepositoryEditor;
use tough::key_source::{LocalKeySource,LocalTargetsKeySource};
use tough::{ExpirationEnforcement, FilesystemTransport, Limits, Repository, Settings};
use ring::rand::SystemRandom;
use ring::signature;
use std::io::prelude::Write;

mod test_utils;

struct RepoPaths {
    root_path: PathBuf,
    datastore: TempDir,
    metadata_base_url: String,
    targets_base_url: String,
}

impl RepoPaths {
    fn new() -> Self {
        let base = test_data().join("tuf-reference-impl");
        RepoPaths {
            root_path: base.join("metadata").join("1.root.json"),
            datastore: TempDir::new().unwrap(),
            metadata_base_url: dir_url(base.join("metadata")),
            targets_base_url: dir_url(base.join("targets")),
        }
    }

    fn root(&self) -> File {
        File::open(&self.root_path).unwrap()
    }
}

fn load_tuf_reference_impl<'a>(paths: &'a mut RepoPaths) -> Repository<'a, FilesystemTransport> {
    Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: &mut paths.root(),
            datastore: paths.datastore.as_ref(),
            metadata_base_url: paths.metadata_base_url.as_str(),
            targets_base_url: paths.targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap()
}

// Test a RepositoryEditor can be created from an existing Repo
#[test]
fn repository_editor_from_repository() {
    // Load the reference_impl repo
    println!("running repo-edit from repo");
    let mut repo_paths = RepoPaths::new();
    let root = repo_paths.root_path.clone();
    let repo = load_tuf_reference_impl(&mut repo_paths);
    let x = RepositoryEditor::from_repo(&root, repo);
    assert!(x.is_ok());

    println!("{:?}", x.unwrap().delegations_map);
}

#[test]
fn gen_and_store_ed25519_keys() {
    let rng = SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.
    
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let mut buffer = File::create(test_data().join("targetskey")).unwrap();
    buffer.write_all(pkcs8_bytes.as_ref()).unwrap();
}

// Load a repository, edit it, and write it to disk. Ensure it loads correctly
// and attempt to read a target
#[test]
fn repo_load_edit_write_load() {
    let mut repo_paths = RepoPaths::new();
    let repo = load_tuf_reference_impl(&mut repo_paths);

    let root = test_data().join("simple-rsa").join("root.json");
    let root_key = test_data().join("snakeoil.pem");
    let key_source = LocalKeySource { path: root_key };
    let targets_key_source = LocalTargetsKeySource { path: test_data().join("targetskey")};
    let timestamp_expiration = Utc::now().checked_add_signed(Duration::days(3)).unwrap();
    let timestamp_version = NonZeroU64::new(1234).unwrap();
    let snapshot_expiration = Utc::now().checked_add_signed(Duration::days(21)).unwrap();
    let snapshot_version = NonZeroU64::new(5432).unwrap();
    let targets_expiration = Utc::now().checked_add_signed(Duration::days(13)).unwrap();
    let targets_version = NonZeroU64::new(789).unwrap();
    let targets_location = test_data().join("tuf-reference-impl").join("targets");
    let target3 = targets_location.join("file3.txt");

    // Load the reference_impl repo
    let mut editor = RepositoryEditor::from_repo(&root, repo).unwrap();

    // Add the required data and a new target
    // We clear the targets first because the reference implementation includes
    // "file1.txt" and "file2.txt". The reference implementation's "targets"
    // directory includes all 3 targets. We want to explicitly add "file3.txt"
    // as a target, and later ensure that "file3" is the only target in the
    // new repo and the only target that gets symlinked. Doing so tests the
    // implementation of `SignedRepository.link_targets()`.
    editor
        .targets_expires(targets_expiration)
        .targets_version(targets_version)
        .snapshot_expires(snapshot_expiration)
        .snapshot_version(snapshot_version)
        .timestamp_expires(timestamp_expiration)
        .timestamp_version(timestamp_version)
        .clear_targets()
        .add_target_path(target3)
        .unwrap();

        // println!("{:?}", editor.delegations_map);

    // Sign the newly updated repo
    let signed_repo = editor.sign_2(&[Box::new(key_source)],&[Box::new(targets_key_source)]).unwrap();

    // Create the directories and write the repo to disk
    let destination = TempDir::new().unwrap();
    let metadata_destination = destination.as_ref().join("metadata-1");
    let targets_destination = destination.as_ref().join("targets-1");
    assert!(signed_repo.write(&metadata_destination).is_ok());
    // assert!(signed_repo
    //     .link_targets(&targets_location, &targets_destination)
    //     .is_ok());

    // Load the repo we just created
    let datastore = TempDir::new().unwrap();
    let metadata_base_url = dir_url(&metadata_destination);
    let targets_base_url = dir_url(&targets_destination);
    let new_repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(&root).unwrap(),
            datastore: datastore.as_ref(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    // Ensure the new repo only has the single target
    assert_eq!(new_repo.targets().signed.targets.len(), 1);

    // The repo shouldn't contain file1 or file2
    // `read_target()` returns a Result(Option<>) which is why we unwrap
    assert!(new_repo.read_target("file1.txt").unwrap().is_none());
    assert!(new_repo.read_target("file2.txt").unwrap().is_none());

    // Read file3.txt
    let mut file_data = Vec::new();
    let file_size = new_repo
        .read_target("file3.txt")
        .unwrap()
        .unwrap()
        .read_to_end(&mut file_data)
        .unwrap();
    assert_eq!(28, file_size);
}
