#!/bin/sh
# Publish a SIGNED release of the version in src/arcount/__init__.py to GitHub.
#
#   1. bump __version__ (and pyproject.toml), commit
#   2. git tag vX.Y.Z && git push origin main vX.Y.Z
#   3. packaging/release.sh            (asks your signing key for a passphrase if it has one)
#
# Signs arcount-X.Y.Z.tar.gz with the key in $ARCOUNT_SIGNING_KEY (default
# ~/.config/arcount-release/signing_key); `arcount update` verifies it against
# src/arcount/data/allowed_signers, the matching public key shipped with every install.
set -eu
cd "$(dirname "$0")/.."
VER=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -c 'import arcount; print(arcount.__version__)')
TAG="v$VER"
KEY="${ARCOUNT_SIGNING_KEY:-$HOME/.config/arcount-release/signing_key}"
[ -f "$KEY" ] || { echo "signing key not found: $KEY" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "tag $TAG does not exist (git tag $TAG)" >&2; exit 1; }
[ "$(git rev-parse "$TAG^{commit}")" = "$(git rev-parse HEAD)" ] || { echo "$TAG is not at HEAD" >&2; exit 1; }
git ls-remote --exit-code --tags origin "$TAG" >/dev/null || { echo "push the tag first: git push origin $TAG" >&2; exit 1; }
OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT
FILE="$OUT/arcount-$VER.tar.gz"
git archive --format=tar.gz --prefix="arcount-$VER/" -o "$FILE" "$TAG"
ssh-keygen -Y sign -f "$KEY" -n arcount-release "$FILE"
# sanity: must verify against the key that ships in the package
ssh-keygen -Y verify -f src/arcount/data/allowed_signers -I arcount-release@whoami-pantheon \
    -n arcount-release -s "$FILE.sig" < "$FILE"
( cd "$OUT" && sha256sum "arcount-$VER.tar.gz" > "arcount-$VER.tar.gz.sha256" )
gh release create "$TAG" "$FILE" "$FILE.sig" "$FILE.sha256" \
    --title "Arcount $VER" --generate-notes --verify-tag
echo "released $TAG"
