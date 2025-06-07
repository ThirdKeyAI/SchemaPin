#!/bin/bash
#
# JavaScript package publishing script for SchemaPin.
#
# This script handles publishing to npm with proper validation and safety checks.
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
JS_DIR="$ROOT_DIR/javascript"
DIST_DIR="$ROOT_DIR/dist"

# Functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_prerequisites() {
    log_info "Checking publishing prerequisites..."
    
    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed"
        return 1
    fi
    log_success "npm is installed"
    
    # Check if we're in the right directory
    if [ ! -f "$JS_DIR/package.json" ]; then
        log_error "package.json not found in $JS_DIR"
        return 1
    fi
    log_success "Found package.json"
    
    # Check if user is logged in to npm
    if ! npm whoami &> /dev/null; then
        log_warning "Not logged in to npm. Run 'npm login' first."
        return 1
    fi
    
    local npm_user=$(npm whoami)
    log_success "Logged in to npm as: $npm_user"
    
    # Check if package exists in dist
    if [ ! -f "$DIST_DIR"/*.tgz ]; then
        log_error "No .tgz package found in $DIST_DIR. Run build_packages.py first."
        return 1
    fi
    log_success "Found package in dist directory"
    
    # Check git status
    if command -v git &> /dev/null && [ -d "$ROOT_DIR/.git" ]; then
        if [ -n "$(git status --porcelain)" ]; then
            log_warning "Git repository has uncommitted changes"
            log_warning "Consider committing changes before publishing"
        else
            log_success "Git repository is clean"
        fi
    fi
    
    return 0
}

validate_package() {
    log_info "Validating package..."
    
    cd "$JS_DIR"
    
    # Run tests
    if ! npm test; then
        log_error "Tests failed"
        return 1
    fi
    log_success "Tests passed"
    
    # Check package.json for required fields
    local package_name=$(node -p "require('./package.json').name")
    local package_version=$(node -p "require('./package.json').version")
    local package_description=$(node -p "require('./package.json').description")
    
    if [ -z "$package_name" ] || [ "$package_name" = "undefined" ]; then
        log_error "Package name is missing"
        return 1
    fi
    
    if [ -z "$package_version" ] || [ "$package_version" = "undefined" ]; then
        log_error "Package version is missing"
        return 1
    fi
    
    if [ -z "$package_description" ] || [ "$package_description" = "undefined" ]; then
        log_error "Package description is missing"
        return 1
    fi
    
    log_success "Package metadata is valid"
    log_info "Package: $package_name@$package_version"
    log_info "Description: $package_description"
    
    # Validate package contents
    if ! npm pack --dry-run; then
        log_error "Package validation failed"
        return 1
    fi
    log_success "Package validation passed"
    
    return 0
}

check_version_exists() {
    local package_name="$1"
    local version="$2"
    
    log_info "Checking if version $version already exists on npm..."
    
    # Check if version exists on npm
    if npm view "$package_name@$version" version &> /dev/null; then
        log_error "Version $version already exists on npm"
        log_error "Please update the version number in package.json"
        return 1
    fi
    
    log_success "Version $version is available"
    return 0
}

publish_to_npm() {
    local tag="$1"
    local registry="$2"
    
    cd "$JS_DIR"
    
    local package_name=$(node -p "require('./package.json').name")
    local package_version=$(node -p "require('./package.json').version")
    
    log_info "Publishing $package_name@$package_version to npm..."
    
    if [ -n "$tag" ]; then
        log_info "Using tag: $tag"
    fi
    
    if [ -n "$registry" ]; then
        log_info "Using registry: $registry"
    fi
    
    # Build npm publish command
    local cmd="npm publish"
    
    if [ -n "$tag" ]; then
        cmd="$cmd --tag $tag"
    fi
    
    if [ -n "$registry" ]; then
        cmd="$cmd --registry $registry"
    fi
    
    # Add access public for scoped packages
    cmd="$cmd --access public"
    
    log_info "Running: $cmd"
    
    if eval "$cmd"; then
        log_success "Successfully published to npm!"
        if [ -n "$registry" ] && [[ "$registry" == *"test"* ]]; then
            log_info "Check your package at: https://www.npmjs.com/package/$package_name"
        else
            log_info "Check your package at: https://www.npmjs.com/package/$package_name"
        fi
        return 0
    else
        log_error "npm publish failed"
        return 1
    fi
}

test_installation() {
    local package_name="$1"
    local version="$2"
    
    log_info "Testing installation of $package_name@$version..."
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Initialize test project
    cat > package.json << EOF
{
  "name": "schemapin-install-test",
  "version": "1.0.0",
  "type": "module"
}
EOF
    
    # Install the package
    if npm install "$package_name@$version"; then
        log_success "Package installation successful"
        
        # Test basic import
        cat > test.js << 'EOF'
import { KeyManager, SchemaPinCore } from 'schemapin';

try {
    const { privateKey, publicKey } = KeyManager.generateKeypair();
    const core = new SchemaPinCore();
    console.log('✅ Basic functionality test passed');
} catch (error) {
    console.error('❌ Basic functionality test failed:', error);
    process.exit(1);
}
EOF
        
        if node test.js; then
            log_success "Functionality test passed"
            cd "$ROOT_DIR"
            rm -rf "$temp_dir"
            return 0
        else
            log_error "Functionality test failed"
            cd "$ROOT_DIR"
            rm -rf "$temp_dir"
            return 1
        fi
    else
        log_error "Package installation failed"
        cd "$ROOT_DIR"
        rm -rf "$temp_dir"
        return 1
    fi
}

publish_workflow() {
    local skip_test="$1"
    
    log_info "Starting JavaScript package publishing workflow..."
    
    # Check prerequisites
    if ! check_prerequisites; then
        return 1
    fi
    
    # Validate package
    if ! validate_package; then
        return 1
    fi
    
    cd "$JS_DIR"
    local package_name=$(node -p "require('./package.json').name")
    local package_version=$(node -p "require('./package.json').version")
    
    # Check if version already exists
    if ! check_version_exists "$package_name" "$package_version"; then
        return 1
    fi
    
    # Confirm publication
    echo
    log_warning "You are about to publish $package_name@$package_version to npm!"
    log_warning "This action cannot be undone. Make sure you have:"
    echo "  - Tested the package thoroughly"
    echo "  - Updated the version number"
    echo "  - Updated the changelog"
    echo "  - Committed all changes to git"
    echo
    
    read -p "Type 'yes' to continue with npm publish: " confirm
    if [ "$confirm" != "yes" ]; then
        log_error "npm publish cancelled"
        return 1
    fi
    
    # Publish to npm
    if ! publish_to_npm; then
        return 1
    fi
    
    # Test installation
    if [ "$skip_test" != "true" ]; then
        log_info "Waiting 30 seconds for npm to propagate..."
        sleep 30
        
        if ! test_installation "$package_name" "$package_version"; then
            log_warning "Installation test failed, but package was published"
        fi
    fi
    
    log_success "JavaScript package publishing completed successfully!"
    return 0
}

# Main script
case "${1:-workflow}" in
    "check")
        check_prerequisites
        ;;
    "validate")
        validate_package
        ;;
    "publish")
        publish_to_npm "$2" "$3"
        ;;
    "test-install")
        cd "$JS_DIR"
        package_name=$(node -p "require('./package.json').name")
        package_version=$(node -p "require('./package.json').version")
        test_installation "$package_name" "$package_version"
        ;;
    "workflow")
        publish_workflow "$2"
        ;;
    *)
        echo "Usage: $0 {check|validate|publish|test-install|workflow}"
        echo
        echo "Commands:"
        echo "  check        - Check prerequisites for publishing"
        echo "  validate     - Validate package before publishing"
        echo "  publish      - Publish to npm (optionally with tag and registry)"
        echo "  test-install - Test installation of published package"
        echo "  workflow     - Complete publishing workflow (default)"
        echo
        echo "Examples:"
        echo "  $0 check"
        echo "  $0 publish beta"
        echo "  $0 workflow skip-test"
        exit 1
        ;;
esac