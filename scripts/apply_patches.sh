#!/bin/bash
#
# ESM Patch Application Script
# Applies Event Stream Model patches to Android 12 AOSP
#
# Usage: bash apply_patches.sh [AOSP_ROOT] [ESM_PATCHES_DIR]
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AOSP_ROOT="${1:-$PWD}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ESM_PATCHES_DIR="${2:-$(dirname "$SCRIPT_DIR")}"
PATCHES_DIR="$ESM_PATCHES_DIR/patches"

# Patch file mapping: [repo_path]="patch_file"
declare -A PATCHES=(
    ["kernel_redbull_source"]="kernel_redbull.patch"
    ["bionic"]="bionic.patch"
    ["frameworks/native"]="frameworks_native.patch"
    ["frameworks/base"]="frameworks_base.patch"
    ["libcore"]="libcore.patch"
    ["build/make"]="build_make.patch"
    ["device/google/redfin"]="device_google_redfin.patch"
)

# Functions
print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check if AOSP root exists
    if [ ! -d "$AOSP_ROOT" ]; then
        print_error "AOSP root directory not found: $AOSP_ROOT"
        exit 1
    fi
    print_success "AOSP root found: $AOSP_ROOT"

    # Check if patches directory exists
    if [ ! -d "$PATCHES_DIR" ]; then
        print_error "Patches directory not found: $PATCHES_DIR"
        exit 1
    fi
    print_success "Patches directory found: $PATCHES_DIR"

    # Check if git is available
    if ! command -v git &> /dev/null; then
        print_error "git is not installed"
        exit 1
    fi
    print_success "git is available"

    # Check if patch files exist
    local missing_patches=0
    for repo in "${!PATCHES[@]}"; do
        local patch_file="$PATCHES_DIR/${PATCHES[$repo]}"
        if [ ! -f "$patch_file" ]; then
            print_warning "Patch file not found: $patch_file"
            missing_patches=$((missing_patches + 1))
        fi
    done

    if [ $missing_patches -gt 0 ]; then
        print_error "$missing_patches patch file(s) missing"
        exit 1
    fi
    print_success "All patch files found"

    echo
}

apply_patch() {
    local repo_path="$1"
    local patch_file="$2"
    local repo_name=$(basename "$repo_path")

    print_info "Applying patch to $repo_name..."

    cd "$AOSP_ROOT/$repo_path"

    # Check if repo is clean
    if ! git diff --quiet; then
        print_warning "Repository has uncommitted changes, stashing..."
        git stash
    fi

    # Try to apply patch
    if git apply --check "$PATCHES_DIR/$patch_file" 2>/dev/null; then
        git apply "$PATCHES_DIR/$patch_file"
        print_success "Patch applied to $repo_name"

        # Show what changed
        local files_changed=$(git diff --name-only | wc -l)
        local lines_added=$(git diff --numstat | awk '{added+=$1} END {print added}')
        local lines_removed=$(git diff --numstat | awk '{removed+=$2} END {print removed}')
        print_info "  Modified files: $files_changed, +$lines_added -$lines_removed lines"

        return 0
    else
        print_error "Failed to apply patch to $repo_name"
        print_info "Attempting 3-way merge..."

        if git apply -3 "$PATCHES_DIR/$patch_file" 2>/dev/null; then
            print_success "Applied with 3-way merge to $repo_name"
            return 0
        else
            print_error "Could not apply patch to $repo_name"
            print_info "You may need to apply this patch manually"
            return 1
        fi
    fi
}

commit_changes() {
    local repo_path="$1"
    local commit_msg="$2"

    cd "$AOSP_ROOT/$repo_path"

    if ! git diff --quiet; then
        git add .
        git commit -m "$commit_msg"
        print_success "Committed changes to $(basename "$repo_path")"
    fi
}

verify_patches() {
    print_header "Verifying Patches"

    local all_verified=true

    # Check kernel for ESM files
    print_info "Checking kernel ESM implementation..."
    if [ -f "$AOSP_ROOT/kernel_redbull_source/kernel/esm.c" ]; then
        print_success "kernel/esm.c exists"
    else
        print_error "kernel/esm.c not found"
        all_verified=false
    fi

    # Check bionic for ESM header
    print_info "Checking bionic ESM syscalls..."
    if grep -q "esm_register" "$AOSP_ROOT/bionic/libc/SYSCALLS.TXT" 2>/dev/null; then
        print_success "ESM syscalls added to bionic"
    else
        print_error "ESM syscalls not found in bionic"
        all_verified=false
    fi

    # Check frameworks/native for ESM usage
    print_info "Checking InputFlinger ESM integration..."
    if grep -q "esm_wait" "$AOSP_ROOT/frameworks/native/services/inputflinger/reader/EventHub.cpp" 2>/dev/null; then
        print_success "InputFlinger uses ESM"
    else
        print_error "InputFlinger doesn't use ESM"
        all_verified=false
    fi

    # Check evdev for duplicate fix
    print_info "Checking evdev duplicate event fix..."
    if grep -q "list_first_or_null_rcu" "$AOSP_ROOT/kernel_redbull_source/drivers/input/evdev.c" 2>/dev/null; then
        print_success "evdev duplicate event fix applied"
    else
        print_error "evdev duplicate event fix not found"
        all_verified=false
    fi

    echo

    if [ "$all_verified" = true ]; then
        print_success "All patches verified successfully!"
        return 0
    else
        print_warning "Some patches may not have applied correctly"
        return 1
    fi
}

print_summary() {
    print_header "Patch Application Summary"

    echo -e "${GREEN}ESM patches have been applied successfully!${NC}"
    echo
    echo "Modified repositories:"
    for repo in "${!PATCHES[@]}"; do
        echo "  • $repo"
    done
    echo
    echo "Next steps:"
    echo "  1. Review changes: cd $AOSP_ROOT && repo diff"
    echo "  2. Build kernel:   see docs/QUICKSTART.md Step 6"
    echo "  3. Build AOSP:     source build/envsetup.sh && lunch aosp_redfin-userdebug && m -j\$(nproc)"
    echo "  4. Flash device:   see docs/QUICKSTART.md Step 7"
    echo
    echo "Documentation:"
    echo "  • Quick Start: $ESM_PATCHES_DIR/docs/QUICKSTART.md"
    echo "  • Technical:   $ESM_PATCHES_DIR/docs/ESM_TECHNICAL.md"
    echo "  • Full Guide:  See ESM_BUILD_HOWTO.md in AOSP root"
    echo
}

main() {
    print_header "ESM Patch Application for Android 12"
    echo "AOSP Root:    $AOSP_ROOT"
    echo "Patches Dir:  $PATCHES_DIR"
    echo

    # Check prerequisites
    check_prerequisites

    # Apply patches
    print_header "Applying Patches"

    local failed_patches=0
    local success_patches=0

    # Apply kernel patch first (most important)
    if apply_patch "kernel_redbull_source" "kernel_redbull.patch"; then
        commit_changes "kernel_redbull_source" "Add ESM support to kernel

- Implement ESM core (kernel/esm.c)
- Add ESM syscalls (esm_register, esm_wait, esm_ctl, is_in_esm_wait)
- Integrate with evdev driver
- Fix duplicate event delivery issue
- Add TASK_EV_WAIT state

ESM provides push-based event delivery for lower latency input."
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    # Apply bionic patch (needed for syscalls)
    if apply_patch "bionic" "bionic.patch"; then
        commit_changes "bionic" "Add ESM syscalls to bionic

- Add syscall definitions to SYSCALLS.TXT
- Create sys/esm.h header with ESM API
- Add event structures and constants"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    # Apply framework patches
    if apply_patch "frameworks/native" "frameworks_native.patch"; then
        commit_changes "frameworks/native" "Integrate ESM with InputFlinger

- Replace epoll_wait with esm_wait in EventHub
- Register input devices with esm_register
- Handle batched event delivery
- Add ESM debug logging"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    if apply_patch "frameworks/base" "frameworks_base.patch"; then
        commit_changes "frameworks/base" "Add ESM awareness to Watchdog

- Check if process is in ESM wait before ANR
- Add JNI for is_in_esm_wait syscall
- Prevent false ANR when InputFlinger waiting on events"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    if apply_patch "libcore" "libcore.patch"; then
        commit_changes "libcore" "Add ESM constants to OsConstants

- Add ESM syscall numbers for Java layer
- Add event type constants"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    # Apply build system patches
    if apply_patch "build/make" "build_make.patch"; then
        commit_changes "build/make" "Update build system for ESM kernel

- Integrate kernel build into AOSP
- Set ESM compile flags"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    if apply_patch "device/google/redfin" "device_google_redfin.patch"; then
        commit_changes "device/google/redfin" "Configure Pixel 5 for ESM

- Enable ESM kernel build
- Add device-specific ESM configuration"
        success_patches=$((success_patches + 1))
    else
        failed_patches=$((failed_patches + 1))
    fi

    echo
    print_info "Applied $success_patches patches successfully"
    if [ $failed_patches -gt 0 ]; then
        print_warning "$failed_patches patches failed"
    fi
    echo

    # Create build.sh symlink
    print_info "Creating build.sh symlink..."
    cd "$AOSP_ROOT"
    if [ -f "build/make/build_esm.sh" ]; then
        ln -sf build/make/build_esm.sh build.sh
        chmod +x build/make/build_esm.sh
        print_success "Created build.sh -> build/make/build_esm.sh"
    else
        print_warning "build_esm.sh not found, symlink not created"
    fi
    echo

    # Verify patches
    verify_patches

    # Print summary
    print_summary

    if [ $failed_patches -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
