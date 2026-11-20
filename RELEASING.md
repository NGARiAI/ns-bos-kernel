# Releasing

A release is a tag. Pushing `vX.Y.Z` builds the release files from that commit,
attests their build provenance and publishes a GitHub release. The workflow
makes the release, not a laptop.

## Cut a release

1. Pick the version: `MAJOR.MINOR.PATCH`, optionally followed by `a`, `b` or
   `rc` and a number (`0.2.0`, `0.2.0rc1`). `0.2.0-rc1` is refused because
   setuptools rewrites it to `0.2.0rc1` inside the wheel.
2. Set `VERSION` in `core/kernel/__init__.py` and `version` in
   `core/kernel/setup.py` to it.
3. In `CHANGELOG.md`, move the `[Unreleased]` entries under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading. That section becomes the release notes
   and cannot be empty.
4. Merge the change through a pull request once `ci-ok` is green.
5. From the merge commit on `master`, check the versions, then tag and push:

       python scripts/release.py check --tag vX.Y.Z
       git tag -a vX.Y.Z -m "vX.Y.Z"
       git push origin vX.Y.Z

## What the workflow does

`.github/workflows/release.yml` runs four jobs. The first two run side by
side; build and attest starts only when both pass, and publish release after
it:

1. **verify tag**: the tag equals `v` plus the version in both version files,
   `CHANGELOG.md` has a section for it, and the tagged commit is on the default
   branch.
2. **ci**: the full CI workflow.
3. **build and attest**: `make build`, then `make smoke` on the wheel. The wheel
   must match, byte for byte, the one the CI build job made on another runner.
   Build provenance is then attested for every file listed in `SHA256SUMS`.
4. **publish release**: checks the files against `SHA256SUMS` again and creates
   the release with the `CHANGELOG.md` section as its notes. A tag that is not
   plain `vX.Y.Z` is marked as a pre-release.

A release holds `ns_bos-X.Y.Z-py3-none-any.whl`, `ns-bos-kernel-X.Y.Z.tar.gz`,
`ns-bos-kernel-X.Y.Z.spdx.json` and `SHA256SUMS`.

Once signed (next section), it also holds `SHA256SUMS.sig`.

## Sign a release

The maintainer signs each release after the workflow publishes it, offline,
with the release key. The repository holds no private key and no workflow
can sign. An OpenSSH key on a FIDO2 security key (`ed25519-sk`) keeps the
private half on the token.

Once, to make the key and show its fingerprint:

    ssh-keygen -t ed25519-sk -C ngari-release -f ngari-release
    ssh-keygen -l -f ngari-release.pub

Publish `ngari-release.pub` and that fingerprint somewhere a buyer can check
apart from the release itself: the repository, the appliance, the contract.

For each release:

    gh release download vX.Y.Z --repo OWNER/REPO --dir vX.Y.Z
    (cd vX.Y.Z && sha256sum -c SHA256SUMS)
    ssh-keygen -Y sign -f ngari-release -n ngari-release vX.Y.Z/SHA256SUMS
    python scripts/release.py verify --dir vX.Y.Z --key ngari-release.pub --version X.Y.Z
    gh release upload vX.Y.Z vX.Y.Z/SHA256SUMS.sig --repo OWNER/REPO

`-Y sign` writes `SHA256SUMS.sig`. The namespace `ngari-release` keeps a
signature made for anything else with the same key from passing as a
release signature. For a release going to a customer site, rebuild the
wheel first (Rebuild and compare).

## Verify a release

    gh release download vX.Y.Z --repo OWNER/REPO --dir vX.Y.Z
    python3 scripts/release.py verify --dir vX.Y.Z --key ngari-release.pub --version X.Y.Z

or `make verify-release DIR=vX.Y.Z KEY=ngari-release.pub VERSION=X.Y.Z`.
With `--version`, a release of any other version is refused even when it
is signed, so an older release cannot pass for the one asked for. It checks the
signature on `SHA256SUMS` with the public key before trusting anything in
it; then that `SHA256SUMS` lists exactly the wheel, source tarball and SBOM
of one version, that the directory holds those, `SHA256SUMS` and
`SHA256SUMS.sig` and nothing else, and that each file matches its line. It
prints the key's fingerprint; compare it with the published one. It needs
`ssh-keygen` (package `openssh-client`) and no network, so it works on an
air-gapped machine. Run a copy of `release.py` you already trust, not the
one inside the tarball being checked. Exit status 0 means verified, 1 not.

Without the script, the same checks by hand, from the directory that holds
`vX.Y.Z/`. `KEY` is the release public key you got from the maintainer,
never a file that came with the release, which anyone could have replaced:

    KEY=/path/to/ngari-release.pub
    ssh-keygen -l -f "$KEY"
    ALLOWED=$(mktemp)
    awk '{print "ngari-release", $1, $2}' "$KEY" > "$ALLOWED"
    ssh-keygen -Y verify -f "$ALLOWED" -I ngari-release -n ngari-release \
        -s vX.Y.Z/SHA256SUMS.sig < vX.Y.Z/SHA256SUMS
    (cd vX.Y.Z && sha256sum -c SHA256SUMS)
    ls -A vX.Y.Z

Compare the fingerprint the first command prints with the published one,
and check that `ls -A` lists the three release files, `SHA256SUMS` and
`SHA256SUMS.sig` and nothing else.

With network access, the attestation also ties each file to the workflow
run and commit that built it:

    gh attestation verify ns_bos-X.Y.Z-py3-none-any.whl --repo OWNER/REPO

## Rebuild and compare

    git switch --detach vX.Y.Z
    make build
    sha256sum dist/ns_bos-X.Y.Z-py3-none-any.whl

The digest must equal the wheel's line in the release's `SHA256SUMS`. File
times in the wheel come from the commit time, and the build tools are the
versions pinned in the dev lock. A rebuild under CPython 3.10, 3.11, 3.12 and
3.13 produced the same wheel on x86_64 Linux.

The SBOM carries a fresh ID and timestamp on every run, so a rebuilt
`SHA256SUMS` never matches; compare the wheel only. If a wheel does differ,
unpack both and run `diff -r`, since compressed bytes can differ across zlib
builds while the files match.

## Requirements

The attestation step needs a public repository, or GitHub Enterprise Cloud for
a private one. Elsewhere the build job fails at that step and nothing is
published. Anyone who can push a `v*` tag can start a release, so restrict tag
creation as described in `CI.md`.

## When a release fails

A failure before the publish job leaves no release. Fix the cause on `master`
through a pull request, delete the tag, and tag the new commit:

    git push origin :refs/tags/vX.Y.Z
    git tag -d vX.Y.Z

If the publish job fails, look at the Releases page first. A release that
exists counts as published: never move its tag or reuse its version, and fix
forward with the next version number.
