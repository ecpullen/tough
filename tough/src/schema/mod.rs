#![allow(clippy::used_underscore_binding)] // #20

mod de;
pub mod decoded;
mod error;
mod iter;
pub mod key;
mod spki;
mod verify;

pub use crate::schema::error::{Error, Result};

use crate::schema::decoded::{Decoded, Hex};
use crate::schema::iter::KeysIter;
use crate::schema::key::Key;
use crate::sign::Sign;
use chrono::{DateTime, Utc};
use olpc_cjson::CanonicalFormatter;
use ring::digest::{Context, digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_plain::{forward_display_to_serde, forward_from_str_to_serde};
use snafu::{ResultExt, ensure};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroU64;
use std::path::Path;
use url::Url;
use regex::Regex;
pub use crate::transport::{FilesystemTransport, Transport};

/// A role type.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum RoleType {
    Root,
    Snapshot,
    Targets,
    Timestamp,
}

forward_display_to_serde!(RoleType);
forward_from_str_to_serde!(RoleType);

/// Common trait implemented by all roles.
pub trait Role: Serialize {
    const TYPE: RoleType;

    fn expires(&self) -> DateTime<Utc>;

    fn version(&self) -> NonZeroU64;

    fn canonical_form(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        self.serialize(&mut ser)
            .context(error::JsonSerialization { what: "role" })?;
        Ok(data)
    }
}

/// A signed metadata object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Signed<T> {
    /// The role that is signed.
    pub signed: T,
    /// A list of signatures and their key IDs.
    pub signatures: Vec<Signature>,
}

/// A signature and the key ID that made it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Signature {
    /// The key ID (listed in root.json) that made this signature.
    pub keyid: Decoded<Hex>,
    /// A hex-encoded signature of the canonical JSON form of a role.
    pub sig: Decoded<Hex>,
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "root")]
pub struct Root {
    pub spec_version: String,
    pub consistent_snapshot: bool,
    pub version: NonZeroU64,
    pub expires: DateTime<Utc>,
    #[serde(deserialize_with = "de::deserialize_keys")]
    pub keys: HashMap<Decoded<Hex>, Key>,
    pub roles: HashMap<RoleType, RoleKeys>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RoleKeys {
    pub keyids: Vec<Decoded<Hex>>,
    pub threshold: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Root {
    pub fn keys(&self, role: RoleType) -> impl Iterator<Item = &Key> {
        KeysIter {
            keyids_iter: match self.roles.get(&role) {
                Some(role_keys) => role_keys.keyids.iter(),
                None => [].iter(),
            },
            keys: &self.keys,
        }
    }

    /// Given an object/key that impls Sign, return the corresponding
    /// key ID from Root
    pub fn key_id(&self, key_pair: &dyn Sign) -> Option<Decoded<Hex>> {
        for (key_id, key) in &self.keys {
            if key_pair.tuf_key() == *key {
                return Some(key_id.clone());
            }
        }
        None
    }
}

impl Role for Root {
    const TYPE: RoleType = RoleType::Root;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "snapshot")]
pub struct Snapshot {
    pub spec_version: String,
    pub version: NonZeroU64,
    pub expires: DateTime<Utc>,
    pub meta: HashMap<String, SnapshotMeta>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SnapshotMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Hashes>,
    pub version: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Hashes {
    pub sha256: Decoded<Hex>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Snapshot {
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Snapshot {
            spec_version,
            version,
            expires,
            meta: HashMap::new(),
            _extra: HashMap::new(),
        }
    }
}
impl Role for Snapshot {
    const TYPE: RoleType = RoleType::Snapshot;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

// We do not handle delegation in this library.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "targets")]
pub struct Targets {
    pub spec_version: String,
    pub version: NonZeroU64,
    pub expires: DateTime<Utc>,
    pub targets: HashMap<String, Target>,
    pub delegations: Option<Delegations>,
    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Target {
    pub length: u64,
    pub hashes: Hashes,
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom: HashMap<String, Value>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Target {
    /// Given a path, returns a Target struct
    pub fn from_path<P>(path: P) -> Result<Target>
    where
        P: AsRef<Path>,
    {
        // Ensure the given path is a file
        let path = path.as_ref();
        if !path.is_file() {
            return error::TargetNotAFile { path }.fail();
        }

        // Get the sha256 and length of the target
        let mut file = File::open(path).context(error::FileOpen { path })?;
        let mut digest = Context::new(&SHA256);
        let mut buf = [0; 8 * 1024];
        let mut length = 0;
        loop {
            match file.read(&mut buf).context(error::FileRead { path })? {
                0 => break,
                n => {
                    digest.update(&buf[..n]);
                    length += n as u64;
                }
            }
        }

        Ok(Target {
            length,
            hashes: Hashes {
                sha256: Decoded::from(digest.finish().as_ref().to_vec()),
                _extra: HashMap::new(),
            },
            custom: HashMap::new(),
            _extra: HashMap::new(),
        })
    }
}

impl Targets {
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Targets {
            spec_version,
            version,
            expires,
            targets: HashMap::new(),
            _extra: HashMap::new(),
            delegations: None,
        }
    }

    pub fn find_target(&self, target_url: &str) -> Result<&Target>{
        match self.targets.get(target_url) {
            Some(target) => return Ok(target),
            None => {
                match &self.delegations {
                    None => return Err(Error::TargetNotFound{target_url:target_url.clone().to_string()}),
                    Some(delegations) => return delegations.find_target(target_url)
                }
            }
        }
    }

    pub fn get_del_role(&self, name:&str) -> Result<&DelegatedRole>{
        self.delegations.as_ref().unwrap().get_del_role(name)
    }

    pub fn get_targets(&self) -> Vec<&Target>{
        let mut targets = Vec::new();
        for target in &self.targets {
            targets.push(target.1);
        }
        if let Some(del) = &self.delegations {
            for t in del.get_targets() {
                targets.push(t);
            }
        }

        targets
    }
}

impl Role for Targets {
    const TYPE: RoleType = RoleType::Targets;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}

//Implementation for delegated targets
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Delegations {
    #[serde(deserialize_with = "de::deserialize_keys")]
    pub keys: HashMap<Decoded<Hex>, Key>,
    pub roles: Vec<DelegatedRole>
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DelegatedRole{
    pub name: String,
    pub keyids: Vec<Decoded<Hex>>,
    pub threshold: NonZeroU64,
    #[serde(flatten)]
    paths: PathSet,
    terminating: bool,
    #[serde(skip)]
    pub targets: Option<Signed<Targets>>
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum PathSet{

    #[serde(rename = "paths")]
    Paths(
        Vec<String>
    ),

    #[serde(rename = "path_hash_prefixes")]
    PathHashPrefixes(
        Vec<String> 
    )
}

impl PathSet{
    fn matched_target(&self, target: &String) -> bool{
        match self{
            Self::Paths(paths) => {
                for path in paths {
                    if Self::matched_path(path, target) {
                        return true
                    }
                }
            }

            Self::PathHashPrefixes(path_prefixes) => {
                for path in path_prefixes {
                    if Self::matched_prefix(path, target) {
                        return true
                    }
                }
            }
        }
        false
    }

    fn matched_prefix(prefix: &String, target: &String) -> bool{
        let temp_target = target.clone();
        let hash = digest(&SHA256, temp_target.as_bytes());
        hash.as_ref().starts_with(prefix.as_bytes())
    }

    fn matched_path(wildcardpath: &String, target: &String) -> bool{
        let mut regex_string = wildcardpath.clone();
        regex_string = regex_string.replace(".", "\\.");
        regex_string = regex_string.replace("*", "[^/]*");
        regex_string = regex_string.replace("?", ".");
        let re = Regex::new(&regex_string).unwrap();
        re.is_match(&target)
    }
}

impl Delegations {
    ///determines if target passes shell wildcard of path
    pub fn check_target(&self, target: &String) -> bool{
        for role in &self.roles {
            if role.paths.matched_target(target) {
                return true
            }
        }
        false
    }

    pub fn verify_paths(&self) -> Result<()>{
        for sub_role in &self.roles {
            for path in match &sub_role.paths{
                PathSet::Paths(paths) => paths,
                PathSet::PathHashPrefixes(paths) => paths
            } {
                if !self.check_target(&path) {
                    return Err(Error::UnmatchedPath{child:path.to_string()})
                }
            }
        }
        Ok(())
    }

    pub fn get_role(&self, role_name: &String) -> Option<&DelegatedRole>{
        for role in &self.roles {
            if &role.name == role_name {
                return Some(&role)
            }
        }
        None
    }

    pub fn verify_role(&self, role: &Signed<Targets>, name: &String) -> Result<()> {
        let role_keys = self
            .get_role(name)
            .expect("Role not found");
        let mut valid = 0;

        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut data, CanonicalFormatter::new());
        role.signed
            .serialize(&mut ser)
            .context(error::JsonSerialization {
                what: format!("Targets role"),
            })?;

        for signature in &role.signatures {
            if role_keys.keyids.contains(&signature.keyid) {
                if let Some(key) = self.keys.get(&signature.keyid) {
                    if key.verify(&data, &signature.sig) {
                        valid += 1;
                    }
                }
            }
        }

        ensure!(
            valid >= u64::from(role_keys.threshold),
            error::SignatureThreshold {
                role: RoleType::Targets,
                threshold: role_keys.threshold,
                valid,
            }
        );
        Ok(())
    }

    pub fn find_target(&self, target_url: &str) -> Result<&Target>{
        for del_role in &self.roles {
            match &del_role.targets{
                Some(targets) => match &targets.signed.find_target(target_url) {
                    Ok(target) => return Ok(target),
                    _ => continue
                },
                None => continue
            }
            
        }
        Err(Error::TargetNotFound{target_url:target_url.to_string()})
    }

    pub fn get_del_role(&self, name:&str)->Result<&DelegatedRole>{
        for del_role in &self.roles {
            if del_role.name == name {
                return Ok(&del_role)
            }
            match del_role.targets.as_ref().unwrap().signed.get_del_role(name) {
                Ok(del) => return Ok(del),
                _ => continue
            }
        }
        Err(Error::TargetNotFound{target_url:name.to_string()})
    }

    pub fn get_targets(&self) -> Vec<&Target> {
        let mut targets = Vec::<&Target>::new();
        for role in &self.roles {
            if let Some(t) = &role.targets {
                for t in t.signed.get_targets() {
                    targets.push(t);
                }
            }
        }
        targets
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "_type")]
#[serde(rename = "timestamp")]
pub struct Timestamp {
    pub spec_version: String,
    pub version: NonZeroU64,
    pub expires: DateTime<Utc>,
    pub meta: HashMap<String, TimestampMeta>,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    #[serde(deserialize_with = "de::extra_skip_type")]
    pub _extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TimestampMeta {
    pub length: u64,
    pub hashes: Hashes,
    pub version: NonZeroU64,

    /// Extra arguments found during deserialization.
    ///
    /// We must store these to correctly verify signatures for this object.
    ///
    /// If you're instantiating this struct, you should make this `HashMap::empty()`.
    #[serde(flatten)]
    pub _extra: HashMap<String, Value>,
}

impl Timestamp {
    pub fn new(spec_version: String, version: NonZeroU64, expires: DateTime<Utc>) -> Self {
        Timestamp {
            spec_version,
            version,
            expires,
            meta: HashMap::new(),
            _extra: HashMap::new(),
        }
    }
}

impl Role for Timestamp {
    const TYPE: RoleType = RoleType::Timestamp;

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn version(&self) -> NonZeroU64 {
        self.version
    }
}


#[test]
fn test_matches_ast(){
    assert!(PathSet::matched_path(&"Metadata/root.json".to_string(), &"Metadata/root.json".to_string()));
    assert!(PathSet::matched_path(&"Metadata/*.json".to_string(), &"Metadata/root.json".to_string()));
    assert!(PathSet::matched_path(&"Metadata/root.*".to_string(), &"Metadata/root.json".to_string()));
    assert!(PathSet::matched_path(&"Metadata/*.*".to_string(), &"Metadata/root.json".to_string()));
}

#[test]
fn test_matches_qtm(){
    assert!(PathSet::matched_path(&"Metadata/root.json".to_string(), &"Metadata/root.json".to_string()));
    assert!(PathSet::matched_path(&"Metadata/root-?.json".to_string(), &"Metadata/root-2.json".to_string()));
    assert!(!PathSet::matched_path(&"Metadata/root-?.json".to_string(), &"Metadata/root-12.json".to_string()));
}

#[test]
fn test_matches_both(){
    assert!(PathSet::matched_path(&"Metadata/root.json".to_string(), &"Metadata/root.json".to_string()));
    assert!(PathSet::matched_path(&"Metadata/root-?.*".to_string(), &"Metadata/root-2.json".to_string()));
    assert!(PathSet::matched_path(&"*/root-?.json".to_string(), &"Data/root-1.json".to_string()));
}