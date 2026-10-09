# Skill Signing with SkillSigner (v1.3 / v1.4)

SchemaPin v1.3 introduced SkillSigner — sign entire skill directories with ECDSA P-256. This produces a `.schemapin.sig` manifest alongside the files, proving no file has been tampered with. Since v1.4 the signature covers the **whole signature document** (name, domain, expiry, lineage fields and the file manifest), not just the root hash, and the directory hashing is length-prefixed and refuses symbolic links. Both changes are selected by `schemapin_version: "1.4"`; 1.3 signatures still verify with a `legacy_signature_format` warning.

---

## What is a Skill Directory?

A skill directory is a folder containing a `SKILL.md` file and optionally other resources:

```
my-skill/
├── SKILL.md            # Skill definition (frontmatter + content)
├── .schemapin.sig      # Signature manifest (created by SkillSigner)
├── examples/           # Optional examples
│   └── usage.md
└── config.json         # Optional configuration
```

SkillSigner hashes every regular file in the directory (except the top-level `.schemapin.sig`), creates a file manifest, builds the signature document, signs it, and writes the result to `.schemapin.sig`. Symbolic links, sockets and other special files are refused: unsigned content must never be reachable from a signed skill. Empty directories and file modes are not covered.

---

## Signing a Skill

### Python

```python
from schemapin.skill import SkillSigner

# Sign the skill directory (writes .schemapin.sig); returns the document as a dict
sig = SkillSigner.sign_skill("./my-skill/", private_key_pem, "example.com")

print(f"Skill signed: {sig['skill_name']}")
print(f"Root hash: {sig['skill_hash']}")
print(f"Files: {list(sig['file_manifest'])}")
```

### JavaScript

```javascript
import { signSkill } from 'schemapin/skill';

const sig = signSkill('./my-skill/', privateKeyPem, 'example.com'); // synchronous
console.log('Skill signed:', sig.skill_name);
console.log('Root hash:', sig.skill_hash);
console.log('Files:', Object.keys(sig.file_manifest));
```

### Go

```go
import "github.com/ThirdKeyAi/schemapin/go/pkg/skill"

sig, err := skill.SignSkill("./my-skill/", privateKeyPEM, "example.com", "", "")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Skill signed: %s\n", sig.SkillName)
```

### Rust

```rust
use std::path::Path;
use schemapin::skill::sign_skill;

let sig = sign_skill(Path::new("./my-skill/"), &private_key_pem, "example.com", None, None)?;
println!("Skill signed: {}", sig.skill_name);
```

---

## The `.schemapin.sig` Format

After signing, `.schemapin.sig` contains:

```json
{
  "schemapin_version": "1.4",
  "skill_name": "my-skill",
  "skill_hash": "sha256:a1b2c3d4e5f6...",
  "signature": "MEUCIQD7y2F8...",
  "signed_at": "2026-02-15T00:00:00Z",
  "domain": "example.com",
  "signer_kid": "sha256:f1e2d3c4b5a6...",
  "file_manifest": {
    "SKILL.md": "sha256:1234abcd...",
    "examples/usage.md": "sha256:5678efgh...",
    "config.json": "sha256:9abc0def..."
  }
}
```

| Field | Description |
|-------|-------------|
| `schemapin_version` | Format version. `1.4` = signed document (current); `1.3` = legacy root-hash-only signature (verify only) |
| `skill_name` | Name of the skill (from directory name or frontmatter) |
| `skill_hash` | `sha256:` + hex of the root hash (see below); verifiers recompute and compare it |
| `signature` | Base64 DER ECDSA P-256 signature over the canonical signature document with `signature` set to `""` |
| `signed_at` | RFC 3339 timestamp of when the skill was signed |
| `expires_at`, `schema_version`, `previous_hash`, `canonicalization` | Optional v1.4 fields; all covered by the signature |
| `domain` | Domain of the signer. Verifiers bind it to the domain they resolved; it is never used as a trust input on its own |
| `signer_kid` | SHA-256 fingerprint of the signing key |
| `file_manifest` | Map of relative file paths to their entry hashes; covered by the signature |

**Hashing (v1.4).** Each entry is hashed as `SHA-256("f" ‖ be64(len(path)) ‖ path ‖ be64(len(content)) ‖ content)` and the root hash is `SHA-256` over `be64(len(path)) ‖ path ‖ entry digest` for every entry in code-point path order. The length prefixes make it impossible to move bytes between a file name and its content without changing the hash. The top-level `.schemapin.sig` is excluded, so you can re-sign a directory without removing the old signature first; a nested file of that name is ordinary content. Entry count (10 000) and total size (256 MiB) are capped. The normative definition is spec section 4b and `tests/cross-language/skill/` is the reference fixture.

---

## Verifying a Signed Skill

### Offline Verification

Verify a skill without HTTP calls using a pre-fetched discovery document:

#### Python

```python
from schemapin.skill import SkillSigner
from schemapin.verification import KeyPinStore

result = SkillSigner.verify_skill_offline(
    "./my-skill/",
    discovery_doc,              # the .well-known document for `domain`
    revocation_doc=None,        # pass a parsed revocation doc to fail closed on revoked keys
    pin_store=KeyPinStore(),
    domain="example.com",       # bind the skill to the domain the discovery doc belongs to
)

if result.valid:
    print("Skill verified successfully")
else:
    print(f"Verification failed: {result.error_code}: {result.error_message}")
```

Always pass `domain`: the signature's own `domain` field is display-only, and a mismatch is a hard `DOMAIN_MISMATCH` failure. Expired signatures fail with `SIGNATURE_EXPIRED` unless you pass `allow_expired=True`. The pin is written only after the signature verified.

**Pass a `revocation_doc`** to fail closed when a publisher has rotated keys. Skill verification honours the same combined inline + standalone revocation rules as schema verification — see the [Revocation guide](revocation.md) for fetching, parsing, and operational guidance.

#### JavaScript

```javascript
import { verifySkillOffline, KeyPinStore } from 'schemapin/skill';

const result = verifySkillOffline(
    './my-skill/',
    discoveryData,
    sig,
    null,
    new KeyPinStore(),
);
```

#### Go

```go
result := skill.VerifySkillOffline("./my-skill/", disc, sig, rev, pinStore, "")
if result.Valid {
    fmt.Println("Skill verified successfully")
}
```

#### Rust

```rust
let result = verify_skill_offline(
    "./my-skill/", &disc, Some(&sig), rev.as_ref(), Some(&pin_store), None,
);
```

---

## Tamper Detection

`detect_tampered_files` compares the current manifest with the signed one and is a diagnostic aid that tells you *which* files changed. For `schemapin_version: "1.4"` documents the manifest is covered by the signature; for legacy 1.3 documents it is not, so an attacker can edit the files and the manifest together — rely on the signature result, not on the diff, for the trust decision.

Check if files have been modified, added, or removed since signing:

### Python

```python
from schemapin.skill import detect_tampered_files, canonicalize_skill

# Get current state of the directory
_, current_manifest = canonicalize_skill("./my-skill/")

# Compare with signed manifest
tampered = detect_tampered_files(current_manifest, sig.file_manifest)

if tampered.modified:
    print(f"Modified files: {tampered.modified}")
if tampered.added:
    print(f"New files: {tampered.added}")
if tampered.removed:
    print(f"Removed files: {tampered.removed}")
```

### JavaScript

```javascript
import { detectTamperedFiles, canonicalizeSkill } from 'schemapin/skill';

const { manifest: currentManifest } = canonicalizeSkill('./my-skill/');
const tampered = detectTamperedFiles(currentManifest, sig.file_manifest);

if (tampered.modified.length > 0) {
    console.log('Modified:', tampered.modified);
}
if (tampered.added.length > 0) {
    console.log('Added:', tampered.added);
}
if (tampered.removed.length > 0) {
    console.log('Removed:', tampered.removed);
}
```

### Go

```go
_, currentManifest, _ := skill.CanonicalizeSkill("./my-skill/")
tampered := skill.DetectTamperedFiles(currentManifest, sig.FileManifest)

if len(tampered.Modified) > 0 {
    fmt.Println("Modified:", tampered.Modified)
}
```

---

## Integration with Skill Loaders

The Symbiont SDK uses SkillSigner to verify skills before loading:

### Python (via symbiont-sdk)

```python
from symbiont import SkillLoader, SkillLoaderConfig

loader = SkillLoader(SkillLoaderConfig(
    load_paths=["/skills/verified", "/skills/community"],
    require_signed=True,   # Only load signed skills
    scan_enabled=True,      # Also run ClawHavoc security scan
))

skills = loader.load_all()
for skill in skills:
    print(f"{skill.name}: signature={skill.signature_status}")
    # VERIFIED, PINNED, UNSIGNED, INVALID, REVOKED
```

### JavaScript (via @symbiont/core)

```javascript
import { SkillLoader } from '@symbiont/core';

const loader = new SkillLoader({
    loadPaths: ['/skills/verified', '/skills/community'],
    requireSigned: true,
    scanEnabled: true,
});

const skills = loader.loadAll();
for (const skill of skills) {
    console.log(`${skill.name}: signature=${skill.signatureStatus}`);
}
```

---

## CI/CD Integration

### Signing in CI

```yaml
# .github/workflows/sign-skill.yml
name: Sign Skill
on:
  push:
    paths: ['skills/**']

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SchemaPin
        run: pip install schemapin

      - name: Sign skill
        env:
          SIGNING_KEY: ${{ secrets.SCHEMAPIN_PRIVATE_KEY }}
        run: |
          echo "$SIGNING_KEY" > /tmp/key.pem
          python -c "
          from schemapin.skill import sign_skill
          sign_skill('./skills/my-skill/', open('/tmp/key.pem').read(), 'example.com')
          "
          rm /tmp/key.pem

      - name: Commit signature
        run: |
          git add skills/my-skill/.schemapin.sig
          git commit -m "Sign skill: my-skill"
          git push
```

### Verification in CI

```yaml
# .github/workflows/verify-skills.yml
name: Verify Skills
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SchemaPin
        run: pip install schemapin

      - name: Verify all skills
        run: |
          python -c "
          import os, json
          from schemapin.skill import verify_skill_offline
          from schemapin.verification import KeyPinStore

          # Load discovery document
          disc = json.load(open('trust/discovery.json'))

          for skill_dir in os.listdir('skills'):
              path = f'skills/{skill_dir}'
              if os.path.isdir(path):
                  sig_path = os.path.join(path, '.schemapin.sig')
                  if os.path.exists(sig_path):
                      sig = json.load(open(sig_path))
                      result = verify_skill_offline(path, disc, sig, None, KeyPinStore())
                      status = 'PASS' if result.valid else 'FAIL'
                      print(f'{skill_dir}: {status}')
                  else:
                      print(f'{skill_dir}: UNSIGNED')
          "
```

---

## Best Practices

1. **Sign at build time** — Include `.schemapin.sig` in your published skill artifacts
2. **Verify before loading** — Always verify skills before executing their content
3. **Use offline verification** — Bundle discovery documents for deterministic verification
4. **Re-sign on changes** — Any file modification invalidates the signature
5. **Exclude `.schemapin.sig`** — The signature file is auto-excluded from its own hash; no manual exclusion needed
6. **Store private keys securely** — Use CI/CD secrets or key management systems
