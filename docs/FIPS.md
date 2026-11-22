# FIPS 140-3

No part of the kernel runs inside a FIPS 140-3 validated module as shipped,
and one primitive it uses, scrypt, is not an approved algorithm. This
document claims no FIPS 140-3 compliance for the kernel. It lists what the
kernel uses and what a FIPS deployment would have to change. Validation
belongs to a cryptographic module and its certificate on the
[CMVP list](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search),
never to an application that calls it.

Measured on 2026-10-31 on Debian 13, Python 3.13.5, against the locked
dependencies:

| Library | OpenSSL it uses | FIPS |
|---------|-----------------|------|
| Python `hashlib`, `hmac` | the system's, 3.5.7 | providers `default` and `legacy` only; `openssl-provider-fips` (3.5.7) is available from Debian but not installed |
| `cryptography` 50.0.0 (PyPI wheel, as locked) | its own, 4.0.1, built into the wheel | off; `backend._enable_fips()` fails with an OpenSSL error, because the wheel carries no FIPS provider |

## Inventory

Every cryptographic call under `core/`, read from the code by
`tests/test_fips_inventory.py`: a new one fails that test until it is
listed here.

| Use | Algorithm and purpose | Where | Provided by | FIPS 140-3 |
|-----|-----------------------|-------|-------------|------------|
| `Fernet` | AES-128-CBC with HMAC-SHA256 (Fernet spec): stored data, agent state, recovery bundle wrapping | `data_plane` | `cryptography` | Approved algorithms (SP 800-38A, FIPS 198-1); not in a validated module as shipped; IVs come from `os.urandom` inside `cryptography` |
| `Fernet.generate_key` | 32 random bytes from `os.urandom`: the master key | `data_plane/keys.py`, `tpm.py` | `cryptography` | Key generation needs an approved random bit generator (SP 800-133) |
| `HKDF` | HKDF-SHA256 of the master key: the audit MAC key and the state key, each with its own info string | `data_plane/__init__.py`, `state.py` | `cryptography` | HKDF is in the OpenSSL FIPS provider; deriving keys from a stored key, not a key-agreement secret, is SP 800-108 territory, a question for the testing lab |
| `hashes.SHA256` | SHA-256 for HKDF, certificate fingerprints and signature checks | `data_plane` | `cryptography` | Approved (FIPS 180-4) |
| `hashlib.sha256` | SHA-256: audit chain and sync ledger hashes, twin checksum, record digests for e-signatures, the digest a card signs | `data_plane`, `network_sync` | Python, system OpenSSL | Approved (FIPS 180-4) |
| `hmac.new` | HMAC-SHA256 with the audit MAC key: each audit entry's MAC | `data_plane/__init__.py` | Python, system OpenSSL | Approved (FIPS 198-1) |
| `hmac.compare_digest` | Constant-time comparison of keys and digests | `data_plane` | Python | Not an algorithm |
| `hashlib.scrypt` | scrypt (N=2^15, r=8, p=1) of the operator passphrase: the recovery bundle key | `data_plane/recovery.py` | Python, system OpenSSL | **Not approved.** The OpenSSL FIPS provider has no scrypt (`OSSL_PROVIDER-FIPS(7)`), so `export-recovery` and `restore` would fail with FIPS on |
| `ec.ECDSA` | ECDSA with SHA-256: checking card signatures (gate, e-signatures) | `data_plane/operator_auth.py` | `cryptography` | Approved (FIPS 186-5) for P-256, P-384, P-521, the only curves accepted |
| `ec.EllipticCurvePublicKey` | Accepts EC certificates on P-256, P-384 or P-521 | `data_plane/operator_auth.py` | `cryptography` | Not an algorithm; other curves are refused |
| `rsa.RSAPublicKey` | Accepts RSA certificates of at least 2048 bits, exponent from 65537 up to below 2^256 | `data_plane/operator_auth.py` | `cryptography` | Not an algorithm; smaller keys are refused (FIPS 186-5) |
| `padding.PKCS1v15` | RSA PKCS#1 v1.5 with SHA-256: checking RSA card signatures | `data_plane/operator_auth.py` | `cryptography` | Approved (FIPS 186-5) |
| `--mechanism ECDSA` | The card signs a SHA-256 digest with raw ECDSA | `data_plane/operator_auth.py` | the PIV/CAC card, through OpenSC | The card's own certificate |
| `--mechanism SHA256-RSA-PKCS` | The card signs with RSA PKCS#1 v1.5 and SHA-256 | `data_plane/operator_auth.py` | the PIV/CAC card, through OpenSC | The card's own certificate |
| `-G ecc256:null:aes128cfb` | Storage primary key: ECC P-256 with AES-128-CFB for the objects under it | `data_plane/tpm.py` | the TPM | Approved algorithms inside the TPM; the chip's own certificate |
| `-g sha256` | SHA-256 name algorithm for the primary and the sealed object; PCR policies use the sha256 bank | `data_plane/tpm.py` | the TPM | Approved algorithm inside the TPM; the chip's own certificate |
| `secrets.token_bytes` | Random bytes: gate challenge nonces (32), recovery bundle salt | `data_plane` | Python, `os.urandom` | Needs an approved random bit generator |
| `secrets.token_hex` | Random hex: e-signature nonce (16 bytes); elsewhere temporary file and message name suffixes, which are not security functions | all packages | Python, `os.urandom` | The e-signature nonce needs an approved random bit generator; the names do not |
| `secrets.token_urlsafe` | The scratch passphrase `keys selftest` uses in its own directory | `data_plane/selftest.py` | Python, `os.urandom` | Test data, not a security function |
| `os.urandom` | Random fill written over a file before `delete()` removes it (best effort) | `data_plane/__init__.py` | the Linux kernel | Not a security function under FIPS 140-3 |
| `uuid.uuid4` | Agent, task and tool call ids | `agent_runtime`, `inference` | Python, `os.urandom` | Not a security function |

## What a FIPS deployment needs

1. **A validated module under every call.** Build `cryptography` from
   source against the system OpenSSL instead of the PyPI wheel, so both it
   and Python's `hashlib` use one libcrypto, and configure that OpenSSL to
   load its FIPS provider by default (`default_properties = fips=yes`). A
   provider is validated only as the exact version and build its CMVP
   certificate names, so check the certificate before relying on a package.
   This changes the hash-pinned locks and the SBOM, which pin wheels.
2. **A recovery bundle without scrypt.** Bundles are scrypt-derived today.
   A FIPS build needs a new bundle version with PBKDF2-HMAC-SHA256 (SP
   800-132), and bundles made with scrypt can then be restored only on a
   machine without FIPS on. This is a format change.
3. **Approved random numbers.** The master key, Fernet's IVs, the recovery
   salt and the challenge and signature nonces come from `os.urandom`, the
   Linux kernel's generator, not from a module's DRBG. Inside
   `cryptography`, Fernet draws its own key and IVs that way, with no
   public way to supply them. That holds up only on an operating system whose
   kernel crypto has its own CMVP certificate and runs in FIPS mode;
   otherwise Fernet would have to be replaced, again a format change.
4. **Algorithm limits**, already in place: card certificates on curves
   other than P-256, P-384 and P-521, RSA under 2048 bits or with an
   exponent under 65537 or of 2^256 or more, and other key types are
   refused when pinning, at
   the gate and when signing, and reported invalid when checking.
5. **Hardware with its own certificates.** The TPM and the PIV/CAC card do
   their own cryptography. Look up each chip's certificate on the CMVP list,
   and check that the TPM runs in its FIPS mode: `tpm2_getcap
   properties-fixed` shows `TPM2_PT_MODES` (the software TPM used in tests
   reports `0x0`). SoftHSM and the software TPM used in tests are not
   validated.
6. **A lab's view of HKDF.** The audit MAC key and the state key are
   derived from the master key with HKDF. Whether that use is approved, or
   needs an SP 800-108 KDF, is for the testing lab.

Release verification (`scripts/release.py verify`, `RELEASING.md`) runs
outside the kernel with OpenSSH and is not covered here.
