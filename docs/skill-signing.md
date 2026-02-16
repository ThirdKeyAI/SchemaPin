# Skill Signing with SkillSigner (v1.3)

SchemaPin v1.3 introduces SkillSigner — sign entire skill directories with ECDSA P-256. This produces a `.schemapin.sig` manifest alongside the files, proving no file has been tampered with.

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

SkillSigner hashes every file in the directory (except `.schemapin.sig` itself), creates a file manifest, signs the root hash, and writes the result to `.schemapin.sig`.

---

## Signing a Skill

### Python

```python
from schemapin.skill import sign_skill

# Sign the skill directory (writes .schemapin.sig)
sig = sign_skill(
    skill_dir="./my-skill/",
    private_key_pem=private_key_pem,
    domain="example.com",
)

print(f"Skill signed: {sig.skill_name}")
print(f"Root hash: {sig.skill_hash}")
print(f"Files: {list(sig.file_manifest.keys())}")
```

### JavaScript

```javascript
import { signSkill } from 'schemapin/skill';

const sig = await signSkill('./my-skill/', privateKeyPem, 'example.com');
console.log('Skill signed:', sig.skillName);
console.log('Root hash:', sig.skillHash);
console.log('Files:', Object.keys(sig.fileManifest));
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
use schemapin::skill::sign_skill;

let sig = sign_skill("./my-skill/", &private_key_pem, "example.com", None, None)?;
println!("Skill signed: {}", sig.skill_name);
```

---

## The `.schemapin.sig` Format

After signing, `.schemapin.sig` contains:

```json
{
  "schemapin_version": "1.3",
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
| `schemapin_version` | Protocol version (`1.3`) |
| `skill_name` | Name of the skill (from directory name or frontmatter) |
| `skill_hash` | SHA-256 hash of the concatenated file hashes (root hash) |
| `signature` | Base64-encoded ECDSA signature over the root hash |
| `signed_at` | ISO 8601 timestamp of when the skill was signed |
| `domain` | Domain of the signer |
| `signer_kid` | SHA-256 fingerprint of the signing key |
| `file_manifest` | Map of relative file paths to their SHA-256 hashes |

The `.schemapin.sig` file is automatically excluded from hashing — you can re-sign a directory without removing the old signature first.

---

## Verifying a Signed Skill

### Offline Verification

Verify a skill without HTTP calls using a pre-fetched discovery document:

#### Python

```python
from schemapin.skill import verify_skill_offline
from schemapin.verification import KeyPinStore

result = verify_skill_offline(
    skill_dir="./my-skill/",
    discovery_data=discovery_doc,
    signature=sig,
    revocation_doc=None,
    pin_store=KeyPinStore(),
)

if result.valid:
    print("Skill verified successfully")
else:
    print(f"Verification failed: {result.error}")
```

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
const tampered = detectTamperedFiles(currentManifest, sig.fileManifest);

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
