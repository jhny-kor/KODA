#!/bin/sh
# Install only in this repository's shared Git directory. Other hooks are kept.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel)
if git -C "$repo_root" config --get core.hooksPath >/dev/null 2>&1; then
    printf '%s\n' 'KODA guard: custom core.hooksPath is configured; refusing to replace its hooks.' >&2
    exit 1
fi
common_dir=$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)
hooks_dir="$common_dir/hooks"
hook_path="$hooks_dir/pre-push"
marker='# KODA GitLab publication guard v1'
if [ -e "$hook_path" ] && ! head -n 3 "$hook_path" | grep -Fqx "$marker"; then
    printf '%s\n' 'KODA guard: an existing pre-push hook is present; it was preserved.' >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' 'KODA guard: python3 is required.' >&2
    exit 1
}
mkdir -p "$hooks_dir"
cp "$script_dir/gitlab_publication_guard.py" "$hooks_dir/koda-publication-guard.py"
cat > "$hook_path" <<'HOOK'
#!/bin/sh
# KODA GitLab publication guard v1
set -eu
hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$hook_dir/koda-publication-guard.py" "$@"
HOOK
chmod 755 "$hook_path" "$hooks_dir/koda-publication-guard.py"
printf '%s\n' "KODA GitLab guard installed: $hook_path"
