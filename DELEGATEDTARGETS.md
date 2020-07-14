# Delegated Targets Readme

## Introduction

Delegated targets creates a chain of trust from a repository owner to its developers. tough allows users to delegate a set of paths from the repository to another person. A delegation chain is cryptographically checked to ensure that the all updated targets are from the developer that signed the metadata. tuftool offers commands to create a new delegated target as a delegatee, add a delegated role as a delegator, and update the targets of a delegated role.

## Workflow

### Add a Delegation

### Edit Targets

## Tools

All tuftool commands use `--role` to define the command users key permissions.

### `create-role`

The `create-role` command creates a new delegated role named `role` with the provided expiration. The created metadata stored in `outdir/metadata`. The new role is signed with the keys provided in `key`. 

* Arguments
    * `--role` 
        * The role to be created
    * `--from` Delegating role (Optional)
        * The role that will delegate this new role default is `targets`
    * `-k, --key` 
        * Key source that will be used to sign the new metadata
    * `-e, --expiration`
        * The expiration of the newly created metadata
    * `-r, --root` 
        * Path to root.json
    * `-m, --metadata-url`
        * Path to the metadata directory for the repository
    * `-o, --outdir` Output Directory
        * Created metadata will be written to `outdir/metadata/role.json`
    * `-v, --version` (Optional)
        * Version default is 1
    * `-t, --threshold` (Optional)
        * The number of signatures required to sign role default is 1

### `add-role`

The `add-role` command adds a role created with `create-role` to `role`’s metadata. Signed metadata for the delegating role and the delegated role are stored in `outdir/metadata`, and need to be added to the repository by a snapshot and timestamp key holder using `update`. If `sign-all` is included, tuftool assumes the keys provided can be used to sign `snapshot.json` and `timestamp.json`, and the set of signed top level metadata and signed metadata for all roles will be written to `outdir/metadata`.

* Arguments
    * `--role` 
        * The delegating role
    * `-d, --delegatee` 
        * The delegatee that should be added to `role`’s metadata
    * `-k, --key` 
        * The key source used to sign `role` (the keys to sign `delegatee` are not needed)
    * `-r, --root` 
        * Path to root.json
    * `-m, --metadata-url`
        * Path to the metadata directory for the repository
    * `-i, --incoming-metadata`
        * Directory of metadata for the role that needs to be added to `role` 
    * `-o, --outdir` 
        * Updated metadata will be written to `outdir/metadata/`
    * `-p, --paths` (Optional)
        * Paths to be delegated to `role`
    * `-hp, --path-hash-prefixes` (Optional)
        * Paths to be delegated `role`
        * If neither `—p` nor `—hp` are present the paths field of the delegation will default to `paths:[]`
    * `-e, --expiration` (Optional)
        * The updated expiration of the delegating role
    * `-v, --version` (Optional)
        * The updated version number of the delegating role defaults to updating version by 1
    * `--sign-all` (Optional)
        * If included signs snapshot and timestamp and outputs signed metadata to `outdir` (assumes snapshot and timestamp keys are included eliminating the need to call `update`)

### `update-delegated-targets`

The `update-delegated-targets` command adds the targets from `add-targets` to the metadata for `role` and copies or system links them to `outdir/targets` based on `link`. The output needs to be added to the repository by a snapshot and timestamp key holder using `update`. If `sign-all` is included, tuftool assumes the keys provided can be used to sign `snapshot.json` and `timestamp.json`, and the set of signed top level metadata and signed metadata for all roles will be written to `outdir/metadata` and the new targets will be linked to `outdir/targets`.

* Arguments
    * `--role` 
        * The delegatee role
    * `-k, --key` 
        * The key source used to sign `role`
    * `-r, --root` 
        * Path to root.json
    * `-m, --metadata-url`
        * Path to the metadata directory for the repository
    * `-t, --add-targets`
        * Directory of updated targets that need to be added to `role` 
    * `-o, --outdir` 
        * Updated metadata will be written to `outdir/metadata/role.json`
        * Targets will be put in `outdir/targets`
    * `-e, --expiration` (Optional)
        * The updated expiration of the delegating role
    * `-v, --version` (Optional)
        * The updated version number of the delegating role defaults to updating version by 1
    * `--sign-all` (Optional)
        * If included signs snapshot and timestamp and outputs signed metadata to `outdir` (assumes snapshot and timestamp keys are included eliminating the need to call `update`)
    * `-l, --link` (Optional)
        * If included links incoming targets to `outdir/targets` instead of copying

### `update`

The `update` command is used to refresh the timestamp and snapshot metadata, it can also add a set of targets to the Targets metadata, lastly, it can load signed metadata and add it to the repository.

* Arguments
    * `-k, --key` 
        * The key source used to sign timestamp and snapshot
    * `--snapshot-version` 
        * The updated snapshot version
    * `--snapshot-expires` 
        * The updated snapshot expiration
    * `--targets-version` 
        * The updated targets version
    * `--targets-expires` 
        * The updated targets expiration
    * `--timestamp-version` 
        * The updated timestamp version
    * `--timestamp-expires` 
        * The updated timestamp expiration
    * `-r, --root` 
        * Path to root.json
    * `-m, --metadata-url`
        * Path to the metadata directory for the repository
    * `-t, --add-targets` (Optional)
        * Directory of updated targets
    * `--role` (Optional)
        * The delegatee role
    * `-i, --incoming-metadata` (Optional)
        * Directory of metadata for the role that needs to be added to `role` 
        * `role` and `incoming-metadata` should both be present or missing
    * `-o, --outdir` 
        * Updated metadata will be written to `outdir/metadata/role.json`
        * Targets will be put in `outdir/targets`
    * `-f, --follow` (Optional)
        * If included symbolic links will be followed for targets
    * `-j, --jobs` (Optional)
        * Number of target hashing threads to run when adding targets

