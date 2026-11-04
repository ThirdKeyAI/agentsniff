#!/usr/bin/env bash
set -euo pipefail
# Context values arrive as environment data, never as shell source.
tag="${RELEASE_TAG:?release tag is required}"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.+-]*)?$ ]]; then
  echo "Invalid release tag" >&2
  exit 1
fi
if [[ "${GITHUB_REF:?}" != "refs/tags/$tag" ]]; then
  echo "Run releases from the matching tag ref" >&2
  exit 1
fi
tag_commit="$(git rev-parse --verify "refs/tags/${tag}^{commit}")"
head_commit="$(git rev-parse HEAD)"
if [[ "$tag_commit" != "$head_commit" || "$head_commit" != "${GITHUB_SHA:?}" ]]; then
  echo "Release tag, event commit, and checkout must match" >&2
  exit 1
fi
printf 'version=%s\n' "$tag" >> "${GITHUB_OUTPUT:?}"
