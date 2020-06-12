// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::File;
use std::io::Read;
use tempfile::TempDir;
use test_utils::{dir_url, test_data};
use tough::{ExpirationEnforcement, Limits, Repository, Settings};

mod test_utils;

#[cfg(feature = "http")]
use tough::HttpTransport;

#[cfg(feature = "http")]
use mockito::mock;

#[cfg(feature = "http")]
use std::str::FromStr;

#[cfg(feature = "http")]
use url::Url;

fn read_to_end<R: Read>(mut reader: R) -> Vec<u8> {
    let mut v = Vec::new();
    reader.read_to_end(&mut v).unwrap();
    v
}

/// Test that `tough` can process repositories generated by [`tuf`], the reference Python
/// implementation.
///
/// [`tuf`]: https://github.com/theupdateframework/tuf
#[test]
fn test_tuf_reference_impl() {
    let base = test_data().join("tuf-reference-impl");
    let datastore = TempDir::new().unwrap();

    let metadata_base_url = &dir_url(base.join("metadata"));
    let targets_base_url = &dir_url(base.join("targets"));

    let repo = Repository::load(
        &tough::FilesystemTransport,
        Settings {
            root: File::open(base.join("metadata").join("1.root.json")).unwrap(),
            datastore: datastore.as_ref(),
            metadata_base_url,
            targets_base_url,
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    assert_eq!(
        read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
        &b"This is an another example target file."[..]
    );
    assert_eq!(
        repo.targets()
            .signed
            .targets
            .get("file1.txt")
            .unwrap()
            .custom
            .get("file_permissions")
            .unwrap(),
        "0644"
    );
    println!("{:?}", repo.targets().signed.delegations);
    assert!(repo.targets().signed.delegations.as_ref().unwrap().check_target(&"file3.txt".to_string()));
    println!("{}", repo.targets().signed.delegations.as_ref().unwrap().check_target(&"file1.txt".to_string()));
    println!("{:?}", repo.get_targets());
}

#[cfg(feature = "http")]
fn create_successful_get_mock(relative_path: &str) -> mockito::Mock {
    let repo_dir = test_data().join("tuf-reference-impl");
    let file_bytes = std::fs::read(&repo_dir.join(relative_path)).unwrap();
    mock("GET", ("/".to_owned() + relative_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/octet-stream")
        .with_body(file_bytes.as_slice())
        .expect(1)
        .create()
}

/// Test that `tough` can process the same reference Python implementation repository over http.
///
#[test]
#[cfg(feature = "http")]
fn test_tuf_http_transport() {
    let repo_dir = test_data().join("tuf-reference-impl");
    let mock_timestamp = create_successful_get_mock("metadata/timestamp.json");
    let mock_snapshot = create_successful_get_mock("metadata/snapshot.json");
    let mock_targets = create_successful_get_mock("metadata/targets.json");
    let mock_file1_txt = create_successful_get_mock("targets/file1.txt");
    let mock_file2_txt = create_successful_get_mock("targets/file2.txt");
    let datastore = TempDir::new().unwrap();
    let base_url = Url::from_str(mockito::server_url().as_str()).unwrap();
    let metadata_base_url = base_url.join("metadata").unwrap().to_string();
    let targets_base_url = base_url.join("targets").unwrap().to_string();
    let transport = HttpTransport::new();
    let repo = Repository::load(
        &transport,
        Settings {
            root: File::open(repo_dir.join("metadata").join("1.root.json")).unwrap(),
            datastore: datastore.as_ref(),
            metadata_base_url: metadata_base_url.as_str(),
            targets_base_url: targets_base_url.as_str(),
            limits: Limits::default(),
            expiration_enforcement: ExpirationEnforcement::Safe,
        },
    )
    .unwrap();

    assert_eq!(
        read_to_end(repo.read_target("file1.txt").unwrap().unwrap()),
        &b"This is an example target file."[..]
    );
    assert_eq!(
        read_to_end(repo.read_target("file2.txt").unwrap().unwrap()),
        &b"This is an another example target file."[..]
    );
    assert_eq!(
        repo.targets()
            .signed
            .targets
            .get("file1.txt")
            .unwrap()
            .custom
            .get("file_permissions")
            .unwrap(),
        "0644"
    );

    mock_timestamp.assert();
    mock_snapshot.assert();
    mock_targets.assert();
    mock_file1_txt.assert();
    mock_file2_txt.assert();
}
