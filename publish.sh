#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Args ─────────────────────────────────────────────────────────────────────
BUMP="${1:-patch}"
if [[ "$BUMP" != "patch" && "$BUMP" != "minor" && "$BUMP" != "major" ]]; then
  echo "Usage: ./publish.sh [patch|minor|major]"
  exit 1
fi

# ── Pre-flight checks ───────────────────────────────────────────────────────
for cmd in node npm docker; do
  command -v "$cmd" >/dev/null || { echo "❌ $cmd not found"; exit 1; }
done

if ! docker info >/dev/null 2>&1; then
  echo "❌ Docker is not running"
  exit 1
fi

# ── Load release config ──────────────────────────────────────────────────────
ENV_RELEASE="$SCRIPT_DIR/.env.release.local"
[[ -f "$ENV_RELEASE" ]] || ENV_RELEASE="$SCRIPT_DIR/.env.release"
if [[ ! -f "$ENV_RELEASE" ]]; then
  echo "❌ No .env.release.local or .env.release found"
  exit 1
fi

# Read NPM_TOKEN from release file (if not already in env)
if [[ -z "${NPM_TOKEN:-}" ]]; then
  NPM_TOKEN=$(grep '^NPM_TOKEN=' "$ENV_RELEASE" | cut -d= -f2- | tr -d '"' | tr -d "'")
fi
if [[ -z "${NPM_TOKEN:-}" ]]; then
  echo "❌ NPM_TOKEN not found in $ENV_RELEASE or environment"
  exit 1
fi

# ── Production .env ──────────────────────────────────────────────────────────
# Copy release config as .env but strip NPM_TOKEN (it's not a build var)
ENV_FILE="$SCRIPT_DIR/.env"
grep -v '^NPM_TOKEN=' "$ENV_RELEASE" > "$ENV_FILE"
echo "✅ Production .env written (from $(basename "$ENV_RELEASE"))"

# ── Bump version ─────────────────────────────────────────────────────────────
cd npm/nullseal
VERSION=$(npm version "$BUMP" --no-git-tag-version | tr -d 'v')
cd "$SCRIPT_DIR"

for pkg in linux-x64 linux-arm64 darwin-arm64; do
  cd "npm/$pkg"
  npm version "$VERSION" --no-git-tag-version --allow-same-version
  cd "$SCRIPT_DIR"
done

# Update optionalDependencies versions
cd npm/nullseal
node -e "
  const pkg = require('./package.json');
  for (const dep of Object.keys(pkg.optionalDependencies)) {
    pkg.optionalDependencies[dep] = '$VERSION';
  }
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"
cd "$SCRIPT_DIR"

# Sync Cargo.toml
sed -i '' "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml

echo "✅ Version bumped to $VERSION"

# ── Build Linux (Docker) ─────────────────────────────────────────────────────
DIST_DIR="$SCRIPT_DIR/.dist"
rm -rf "$DIST_DIR"

for arch in amd64 arm64; do
  case "$arch" in
    amd64) PKG="linux-x64" ;;
    arm64) PKG="linux-arm64" ;;
  esac

  echo "🔨 Building linux/$arch via Docker..."
  mkdir -p "npm/$PKG/bin"
  docker buildx build \
    -f Dockerfile.linux \
    --platform "linux/$arch" \
    --output "type=local,dest=npm/$PKG/bin" \
    .
  chmod +x "npm/$PKG/bin/nullseal"
  echo "  ✅ $PKG"
done

# ── Build macOS arm64 (native) ────────────────────────────────────────────────
echo "🔨 Building macOS arm64 (native)..."
cargo build --release --target aarch64-apple-darwin
mkdir -p npm/darwin-arm64/bin
cp target/aarch64-apple-darwin/release/nullseal npm/darwin-arm64/bin/nullseal
chmod +x npm/darwin-arm64/bin/nullseal
echo "  ✅ darwin-arm64"

echo "✅ All platforms built"

# ── Publish to npm ───────────────────────────────────────────────────────────
echo ""
echo "📦 Publishing v$VERSION to npm..."
echo ""

# Write .npmrc with token (no npm login needed)
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > "$SCRIPT_DIR/.npmrc"

for pkg in linux-x64 linux-arm64 darwin-arm64; do
  echo "  Publishing @nullseal/$pkg..."
  cd "npm/$pkg"
  npm publish --access public --userconfig "$SCRIPT_DIR/.npmrc"
  cd "$SCRIPT_DIR"
done

echo "  Publishing nullseal..."
cd npm/nullseal
npm publish --access public --userconfig "$SCRIPT_DIR/.npmrc"
cd "$SCRIPT_DIR"

rm -f "$SCRIPT_DIR/.npmrc"

# ── Git commit & tag ─────────────────────────────────────────────────────────
# Restore local dev .env
cat > "$ENV_FILE" <<'EOF'
CLI_APPS_CORE_URL=http://127.0.0.1:3001
CLI_APPS_USER_URL=http://127.0.0.1:3000
EOF

cd "$SCRIPT_DIR/.."
git add cli-rs/
git commit -m "cli: v$VERSION"
git tag "cli-v$VERSION"
git push && git push --tags

echo ""
echo "🚀 Published nullseal@$VERSION"
