// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::editor::keys::get_root_keys;
use crate::editor::keys::get_targets_keys;
use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::{
    Role, RoleType, Root, Signature, Signed, Snapshot, Target, Targets, Timestamp,
};
use olpc_cjson::CanonicalFormatter;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SecureRandom;
use serde::Serialize;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::os::unix::fs::symlink;
use std::path::Path;
use walkdir::WalkDir;

/// A signed role, including its serialized form (`buffer`) which is meant to
/// be written to file. The `sha256` and `length` are calculated from this
/// buffer and included in metadata for other roles, which makes it
/// imperative that this buffer is what is written to disk.
///
/// Convenience methods are provided on `SignedRepository` to ensure that
/// each role's buffer is written correctly.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedRole<T> {
    pub(crate) signed: Signed<T>,
    pub(crate) buffer: Vec<u8>,
    pub(crate) sha256: [u8; SHA256_OUTPUT_LEN],
    pub(crate) length: u64,
}

impl<T> SignedRole<T>
where
    T: Role + Serialize,
{
    pub fn new(
        role: T,
        root: &Root,
        keys: &[Box<dyn KeySource>],
        rng: &dyn SecureRandom,
    ) -> Result<Self> {
        let root_keys = get_root_keys(root, keys)?;

        let role_keys = root.roles.get(&T::TYPE).context(error::NoRoleKeysinRoot {
            role: T::TYPE.to_string(),
        })?;
        // Ensure the keys we have available to us will allow us
        // to sign this role. The role's key ids must match up with one of
        // the keys provided.
        let (signing_key_id, signing_key) = root_keys
            .iter()
            .find(|(keyid, _signing_key)| role_keys.keyids.contains(&keyid))
            .context(error::SigningKeysNotFound {
                role: T::TYPE.to_string(),
            })?;

        // Create the `Signed` struct for this role. This struct will be
        // mutated later to contain the signatures.
        let mut role = Signed {
            signed: role,
            signatures: Vec::new(),
        };

        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        role.signed
            .serialize(&mut ser)
            .context(error::SerializeRole {
                role: T::TYPE.to_string(),
            })?;
        let sig = signing_key.sign(&data, rng)?;

        // Add the signatures to the `Signed` struct for this role
        role.signatures.push(Signature {
            keyid: signing_key_id.clone(),
            sig: sig.into(),
        });

        // Serialize the newly signed role, and calculate its length and
        // sha256.
        let mut buffer = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole {
            role: T::TYPE.to_string(),
        })?;
        buffer.push(b'\n');
        let length = buffer.len() as u64;

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

        // Create the `SignedRole` containing, the `Signed<role>`, serialized
        // buffer, length and sha256.
        let signed_role = SignedRole {
            signed: role,
            buffer,
            sha256,
            length,
        };

        Ok(signed_role)
    }

    pub fn from_signed(role: Signed<T>) -> Result<SignedRole<T>> {
        // Serialize the role, and calculate its length and
        // sha256.
        let mut buffer = serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole {
            role: T::TYPE.to_string(),
        })?;
        buffer.push(b'\n');
        let length = buffer.len() as u64;

        let mut sha256 = [0; SHA256_OUTPUT_LEN];
        sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

        // Create the `SignedRole` containing, the `Signed<role>`, serialized
        // buffer, length and sha256.
        let signed_role = SignedRole {
            signed: role,
            buffer,
            sha256,
            length,
        };

        Ok(signed_role)
    }

    /// creates a map of all signed targets roles excluding the toplevel Targets
    ///  if `include_all`, throw error if needed keys are not present if not just ignore
    pub fn new_targets(
        role: &Targets,
        keys: &[Box<dyn KeySource>],
        rng: &dyn SecureRandom,
        include_all: bool,
    ) -> Result<HashMap<String, SignedRole<Targets>>> {
        let mut signed_roles = HashMap::new();
        if let Some(delegations) = &role.delegations {
            if delegations.roles.is_empty() {
                return Ok(signed_roles);
            }
            let root_keys = get_targets_keys(&delegations, keys)?;
            for role in &delegations.roles {
                let name = role.name.clone();
                let role_keys = role.keys();
                // Ensure the keys we have available to us will allow us
                // to sign this role. The role's key ids must match up with one of
                // the keys provided.

                // Create the `Signed` struct for this role. This struct will be
                // mutated later to contain the signatures.

                //only sign targets that we have keys for without throwing an error
                //delegations allow a key to sign some roles without having to sign them all
                if let Some(targets) = &role.targets {
                    let role = if let Some((signing_key_id, signing_key)) = root_keys
                        .iter()
                        .find(|(keyid, _signing_key)| role_keys.keyids.contains(&keyid))
                    {
                        let mut role = Signed {
                            signed: targets.clone().signed,
                            signatures: Vec::new(),
                        };
                        let mut data = Vec::new();
                        let mut ser = serde_json::Serializer::with_formatter(
                            &mut data,
                            CanonicalFormatter::new(),
                        );
                        role.signed
                            .serialize(&mut ser)
                            .context(error::SerializeRole {
                                role: T::TYPE.to_string(),
                            })?;
                        let sig = signing_key.sign(&data, rng)?;

                        // Add the signatures to the `Signed` struct for this role
                        role.signatures.push(Signature {
                            keyid: signing_key_id.clone(),
                            sig: sig.into(),
                        });

                        role
                    } else if include_all {
                        delegations
                            .verify_role(targets, &name)
                            .context(error::KeyNotFound { role: name.clone() })?;
                        targets.clone()
                    } else {
                        targets.clone()
                    };

                    // Serialize the newly signed role, and calculate its length and
                    // sha256.
                    let mut buffer =
                        serde_json::to_vec_pretty(&role).context(error::SerializeSignedRole {
                            role: T::TYPE.to_string(),
                        })?;
                    buffer.push(b'\n');
                    let length = buffer.len() as u64;

                    let mut sha256 = [0; SHA256_OUTPUT_LEN];
                    sha256.copy_from_slice(digest(&SHA256, &buffer).as_ref());

                    signed_roles.extend(SignedRole::<Targets>::new_targets(
                        &role.signed.clone(),
                        keys,
                        rng,
                        include_all,
                    )?);
                    // Create the `SignedRole` containing, the `Signed<role>`, serialized
                    // buffer, length and sha256.
                    let signed_role = SignedRole {
                        signed: role,
                        buffer,
                        sha256,
                        length,
                    };
                    signed_roles.insert(name, signed_role);
                }
            }
        }
        Ok(signed_roles)
    }

    pub fn signed(&self) -> &Signed<T> {
        &self.signed
    }

    pub fn buffer(&self) -> &Vec<u8> {
        &self.buffer
    }

    pub fn sha256(&self) -> &[u8] {
        &self.sha256
    }

    pub fn length(&self) -> &u64 {
        &self.length
    }

    /// Write the current role's buffer to the given directory with the
    /// appropriate file name.
    pub fn write<P>(&self, outdir: P, consistent_snapshot: bool) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let outdir = outdir.as_ref();
        std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;

        let filename = match T::TYPE {
            RoleType::Targets => {
                if consistent_snapshot {
                    format!("{}.targets.json", self.signed.signed.version())
                } else {
                    "targets.json".to_string()
                }
            }
            RoleType::Snapshot => {
                if consistent_snapshot {
                    format!("{}.snapshot.json", self.signed.signed.version())
                } else {
                    "snapshot.json".to_string()
                }
            }
            RoleType::Timestamp => "timestamp.json".to_string(),
            RoleType::Root => format!("{}.root.json", self.signed.signed.version()),
        };

        let path = outdir.join(filename);
        std::fs::write(&path, &self.buffer).context(error::FileWrite { path })
    }

    /// Write the current delegated role's buffer to the given directory with the
    /// appropriate file name.
    pub fn write_del_role<P>(&self, outdir: P, consistent_snapshot: bool, name: &str) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let outdir = outdir.as_ref();
        std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;

        let path = outdir.join(if consistent_snapshot {
            format!("{}.{}.json", self.signed.signed.version(), name)
        } else {
            format!("{}.json", name)
        });
        std::fs::write(&path, &self.buffer).context(error::FileWrite { path })
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// A set of signed TUF Repository metadata.
///
/// This metadata represents a signed TUF repository and provides the ability
/// to write the metadata to disk.
///
/// Note: without the target files, the repository cannot be used. It is up
/// to the user to ensure all the target files referenced by the metadata are
/// available. There are convenience methods to help with this.
#[derive(Debug, PartialEq)]
pub struct SignedRepository {
    pub(crate) root: SignedRole<Root>,
    pub(crate) targets: SignedRole<Targets>,
    pub(crate) snapshot: SignedRole<Snapshot>,
    pub(crate) timestamp: SignedRole<Timestamp>,
    pub(crate) delegations: HashMap<String, SignedRole<Targets>>,
}

impl SignedRepository {
    /// Writes the metadata to the given directory. If consistent snapshots
    /// are used, the appropriate files are prefixed with their version.
    pub fn write<P>(&self, outdir: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let consistent_snapshot = self.root.signed.signed.consistent_snapshot;
        self.root.write(&outdir, consistent_snapshot)?;
        self.targets.write(&outdir, consistent_snapshot)?;
        self.snapshot.write(&outdir, consistent_snapshot)?;
        self.timestamp.write(&outdir, consistent_snapshot)?;
        for (key, targets) in &self.delegations {
            targets.write_del_role(&outdir, consistent_snapshot, &key)?;
        }
        Ok(())
    }

    /// Crawls a given directory and symlinks any targets found to the given
    /// "out" directory. If consistent snapshots are used, the target files
    /// are prefixed with their `sha256`.
    ///
    /// For each file found in the `indir`, the method gets the filename and
    /// if the filename exists in `Targets`, the file's sha256 is compared
    /// against the data in `Targets`. If this data does not match, the
    /// method will fail. If all is well, the target is symlinked.
    pub fn link_targets<P1, P2>(&self, indir: P1, outdir: P2) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        link_targets(
            indir,
            outdir,
            &self.targets.signed.signed,
            self.root.signed.signed.consistent_snapshot,
        )
    }
}

/// Crawls a given directory and symlinks any targets found to the given
/// "out" directory. If consistent snapshots are used, the target files
/// are prefixed with their `sha256`.
///
/// For each file found in the `indir`, the method gets the filename and
/// if the filename exists in `Targets`, the file's sha256 is compared
/// against the data in `Targets`. If this data does not match, the
/// method will fail. If all is well, the target is symlinked.
pub fn link_targets<P1, P2>(
    indir: P1,
    outdir: P2,
    targets: &Targets,
    consistent_snapshot: bool,
) -> Result<()>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
   
    let outdir = outdir.as_ref();
    let indir = indir.as_ref();
    std::fs::create_dir_all(outdir).context(error::DirCreate { path: outdir })?;

    // Get the absolute path of the indir and outdir
    let abs_indir = std::fs::canonicalize(indir).context(error::AbsolutePath { path: indir })?;
    let abs_outdir = std::fs::canonicalize(outdir).context(error::AbsolutePath { path: outdir })?;
    let repo_targets = if consistent_snapshot {
        targets.targets_map_consistent()
    }else {
        targets.targets_map()
    };

    println!("indir: {:?}", abs_indir);
    println!("outdir: {:?}", abs_outdir);

    // Walk the absolute path of the indir. Using the absolute path here
    // means that `entry.path()` call will return its absolute path.
    let walker = WalkDir::new(&abs_indir).follow_links(true);
    for entry in walker {
        let entry = entry.context(error::WalkDir {
            directory: &abs_indir,
        })?;

        // If the entry is not a file, move on
        if !entry.file_type().is_file() {
            continue;
        };

        // If the entry is a file, get the filename
        let file_name = entry
            .file_name()
            .to_str()
            .context(error::PathUtf8 { path: entry.path() })?;
        println!("file: {}", file_name);
        // Use the file name to see if a target exists in the repo
        // with that name. If so...
        let repo_target = match repo_targets.get(file_name) {
            Some(repo_target) => repo_target,
            None => continue,
        };
        println!("exists");
        // create a Target object using the entry's path, and then...
        let target_from_path = Target::from_path(entry.path())
            .context(error::TargetFromPath { path: entry.path() })?;

        // compare the hashes of the target from the repo and the
        // target we just created. If they are the same, this must
        // be the same file, symlink it.
        ensure!(
            target_from_path.hashes.sha256 == repo_target.hashes.sha256,
            error::HashMismatch {
                context: "target",
                calculated: hex::encode(target_from_path.hashes.sha256),
                expected: hex::encode(&repo_target.hashes.sha256),
            }
        );

        let dest = if consistent_snapshot {
            abs_outdir.join(format!(
                "{}.{}",
                hex::encode(&target_from_path.hashes.sha256),
                file_name
            ))
        } else {
            abs_outdir.join(&file_name)
        };

        symlink(entry.path(), &dest).context(error::LinkCreate { path: &dest })?;
    }

    Ok(())
}
