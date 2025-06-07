# GitHub Actions Workflows for SchemaPin

This directory contains automated release workflows for the SchemaPin dual-language project.

## Workflows

### 1. `release-npm.yml` - npm Package Release
Handles automated publishing of the JavaScript package to npm registry.

**Triggers:**
- Git tags matching `v*` pattern
- Manual dispatch with options

**Features:**
- Version consistency validation
- Comprehensive testing (unit tests, linting)
- Package installation testing
- Duplicate version checking
- Dry run support
- GitHub release creation

### 2. `release-pypi.yml` - PyPI Package Release
Handles automated publishing of the Python package to PyPI.

**Triggers:**
- Git tags matching `v*` pattern
- Manual dispatch with options

**Features:**
- Version consistency validation
- Quality checks (pytest, ruff, bandit)
- Test PyPI publishing first
- Production PyPI publishing
- CLI tools validation
- Installation testing from both registries

### 3. `release-combined.yml` - Dual Package Release
Orchestrates release of both npm and PyPI packages simultaneously.

**Triggers:**
- Git tags matching `v*` pattern
- Manual dispatch with granular control options

**Features:**
- Coordinated dual-package release
- Individual package selection (npm-only, pypi-only)
- Comprehensive validation pipeline
- Unified GitHub release creation

## Required Secrets

Configure these secrets in your GitHub repository settings (`Settings > Secrets and variables > Actions`):

### npm Publishing
- **`NPM_TOKEN`**: npm authentication token
  - Generate at: https://www.npmjs.com/settings/tokens
  - Type: "Automation" token with "Publish" permission
  - Scope: Can be limited to specific packages

### PyPI Publishing
- **`PYPI_API_TOKEN`**: PyPI API token for production releases
  - Generate at: https://pypi.org/manage/account/token/
  - Scope: "Entire account" or specific to schemapin project
  
- **`TEST_PYPI_API_TOKEN`**: Test PyPI API token for testing
  - Generate at: https://test.pypi.org/manage/account/token/
  - Scope: "Entire account" or specific to schemapin project

## Usage

### Automatic Release (Recommended)
1. Update version numbers in both `javascript/package.json` and `python/pyproject.toml`
2. Commit changes and push to main branch
3. Create and push a git tag:
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```
4. Workflows will automatically trigger and publish packages

### Manual Release
1. Go to GitHub Actions tab
2. Select desired workflow
3. Click "Run workflow"
4. Configure options:
   - **Tag**: Version to release (e.g., v1.2.0)
   - **Dry run**: Test without publishing
   - **Package selection**: Choose npm-only, pypi-only, or both

## Workflow Steps

### Validation Phase
1. **Version Consistency**: Ensures JavaScript and Python versions match
2. **Code Quality**: Runs tests, linting, and security checks
3. **Build Validation**: Verifies packages can be built successfully

### Testing Phase
1. **Unit Tests**: Runs comprehensive test suites
2. **Package Installation**: Tests actual package installation
3. **Functionality**: Validates basic package functionality
4. **CLI Tools**: Tests command-line tool availability (Python)

### Publishing Phase
1. **Test Registries**: Publishes to Test PyPI first (Python)
2. **Production Registries**: Publishes to npm and PyPI
3. **Verification**: Tests installation from production registries
4. **GitHub Release**: Creates release with changelog and links

## Configuration Files

### `.npmrc.template`
Template for npm configuration. Copy to `.npmrc` in your home directory or project root.

### `.pypirc.template`
Template for PyPI configuration. Copy to `~/.pypirc` and configure with your credentials.

## Best Practices

### Version Management
- Keep versions synchronized between JavaScript and Python packages
- Use semantic versioning (e.g., 1.2.3)
- Update CHANGELOG.md before releases

### Testing Strategy
- Always test with dry runs first
- Use Test PyPI for Python package validation
- Verify installation in clean environments

### Security
- Use API tokens instead of passwords
- Limit token scopes to minimum required permissions
- Rotate tokens regularly
- Never commit tokens to repository

### Release Process
1. **Development**: Make changes in feature branches
2. **Testing**: Ensure all tests pass locally
3. **Version Bump**: Update version numbers consistently
4. **Documentation**: Update CHANGELOG.md and README.md
5. **Tagging**: Create git tag for release
6. **Monitoring**: Watch workflow execution and verify published packages

## Troubleshooting

### Common Issues

**Version Mismatch**
- Ensure `javascript/package.json` and `python/pyproject.toml` have identical versions
- Check `python/setup.py` version if using legacy setup

**Authentication Failures**
- Verify API tokens are correctly configured in GitHub secrets
- Check token permissions and expiration dates
- Ensure token scopes include package publishing

**Test Failures**
- Run tests locally before pushing tags
- Check for environment-specific issues
- Verify all dependencies are properly declared

**Package Already Exists**
- Version numbers cannot be reused on npm/PyPI
- Increment version number and create new tag
- Use pre-release versions for testing (e.g., 1.2.3-beta.1)

### Manual Recovery
If workflows fail, you can manually publish using existing scripts:
```bash
# npm package
cd javascript && npm publish

# Python package
cd python && python -m build && twine upload dist/*
```

## Monitoring

### Success Indicators
- ✅ All workflow steps complete successfully
- ✅ Packages appear on npm and PyPI registries
- ✅ GitHub release is created with proper changelog
- ✅ Installation tests pass from production registries

### Failure Indicators
- ❌ Test failures in validation phase
- ❌ Authentication errors during publishing
- ❌ Version conflicts or duplicate versions
- ❌ Package installation failures

Monitor workflow execution in the GitHub Actions tab and check package registry pages to confirm successful publication.