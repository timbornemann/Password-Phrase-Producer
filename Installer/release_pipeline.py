"""Release-event orchestration. The detached signature is uploaded last as the ready marker."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "update-manifest.json"
SIGNATURE = "update-manifest.sig"


def release_version(tag: str) -> tuple[str, int]:
    match = re.fullmatch(r"v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))", tag)
    if not match:
        raise ValueError("Use a stable release tag such as 2.6.0 or v2.6.0 (three numeric components).")
    version = match[1]
    major, minor, patch = map(int, version.split("."))
    if major > 2099 or minor > 999 or patch > 999:
        raise ValueError("Supported version ranges: major 0..2099, minor/patch 0..999.")
    code = major * 1_000_000 + minor * 1_000 + patch
    if code == 0:
        raise ValueError("Version 0.0.0 cannot be released.")
    return version, code


def ready_marker(release: dict) -> bool:
    return any(a["name"] == SIGNATURE and a.get("state") == "uploaded" and a["size"] == 64
               for a in release.get("assets", []))


def validate_release(release: dict, release_id: int, tag: str) -> tuple[str, int]:
    if release["id"] != release_id or release["tag_name"] != tag:
        raise ValueError("The release identity/tag changed. Create a new release instead.")
    if release["draft"] or release["prerelease"]:
        raise ValueError("Only published stable releases may build or receive update packages.")
    return release_version(tag)


def validate_order(releases: list[dict], release_id: int, tag: str) -> None:
    _, current_code = release_version(tag)
    for other in releases:
        if other["id"] == release_id or other["draft"] or other["prerelease"]:
            continue
        try:
            _, other_code = release_version(other["tag_name"])
        except ValueError:
            continue
        if other_code >= current_code:
            raise ValueError("The release version must be higher than every previous stable release; versions are never reused.")


def ensure_mutable(release: dict) -> None:
    if release.get("immutable"):
        raise ValueError("This release is immutable and cannot receive build assets. This release-event workflow requires mutable releases.")


def reject_legacy_release(release: dict) -> None:
    if any(a["name"].endswith("_SHA256.txt") and a.get("state") == "uploaded" for a in release.get("assets", [])):
        raise ValueError("This version was already published by the previous release workflow. Choose a new version/tag.")


class GitHub:
    def __init__(self, repository: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Invalid GitHub repository.")
        self.repository = repository

    def run(self, *args: str) -> str:
        result = subprocess.run(["gh", *args], check=False, capture_output=True, text=True, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"GitHub command failed ({args[0]}); no ready marker will be added. {result.stderr.strip()}")
        return result.stdout

    def release(self, release_id: int) -> dict:
        return json.loads(self.run("api", f"repos/{self.repository}/releases/{release_id}"))

    def releases(self) -> list[dict]:
        pages = json.loads(self.run("api", f"repos/{self.repository}/releases?per_page=100", "--paginate", "--slurp"))
        return [release for page in pages for release in page]

    def delete_asset(self, asset_id: int) -> None:
        self.run("api", "--method", "DELETE", f"repos/{self.repository}/releases/assets/{asset_id}")

    def upload(self, tag: str, paths: list[Path]) -> None:
        self.run("release", "upload", tag, *(str(p) for p in paths), "--repo", self.repository)

    def download(self, tag: str, names: list[str], directory: Path) -> None:
        patterns = [argument for name in names for argument in ("--pattern", name)]
        self.run("release", "download", tag, "--repo", self.repository, "--dir", str(directory), *patterns)


def verify_packages(directory: Path) -> None:
    subprocess.run(["dotnet", "run", "--project", str(ROOT / "ReleaseTools/ReleaseTools.csproj"),
                    "-c", "Release", "--no-build", "--", "verify", str(directory),
                    str(ROOT / "Password Phrase Producer/Resources/UpdateSigningPublicKey.pem")], check=True)


def prepare(github: GitHub, release_id: int, tag: str, directory: Path) -> dict[str, str]:
    current = github.release(release_id)
    version, code = validate_release(current, release_id, tag)
    result = {"version": version, "build": str(code), "tag": tag, "release_id": str(release_id), "build_needed": "false"}
    if ready_marker(current):
        return result  # Duplicate published/released events and reruns cannot replace a sealed release.
    reject_legacy_release(current)
    ensure_mutable(current)
    validate_order(github.releases(), release_id, tag)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "release-notes.md").write_text((current.get("body") or f"Password Phrase Producer {version}")[:16000], encoding="utf-8")
    result["build_needed"] = "true"
    return result


def require_uploaded_assets(release: dict, expected_sizes: dict[str, int]) -> None:
    for name, size in expected_sizes.items():
        matches = [a for a in release.get("assets", []) if a["name"] == name]
        if len(matches) != 1 or matches[0].get("state") != "uploaded" or matches[0]["size"] != size:
            raise ValueError(f"Release asset is not fully uploaded: {name}. The update remains unavailable.")


def publish(github: GitHub, release_id: int, tag: str, directory: Path, verify=verify_packages) -> None:
    verify(directory)
    manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    version, code = release_version(tag)
    if (manifest["releaseTag"], manifest["version"], manifest["buildNumber"]) != (tag, version, code):
        raise ValueError("The signed artifacts do not match the requested release tag/version.")
    current = github.release(release_id)
    validate_release(current, release_id, tag)
    if ready_marker(current):
        raise ValueError("This release has already been sealed. Published packages will not be overwritten.")
    reject_legacy_release(current)
    ensure_mutable(current)
    validate_order(github.releases(), release_id, tag)
    paths = [directory / a["fileName"] for a in manifest["artifacts"]] + [directory / MANIFEST]
    # verify() validates signed filenames before any deletion, upload or local path is used.
    expected_sizes = {p.name: p.stat().st_size for p in paths}
    owned_names = set(expected_sizes) | {SIGNATURE}
    # A failed attempt may leave partial assets. Clear its marker first; never touch unrelated attachments.
    for asset in sorted(current.get("assets", []), key=lambda a: a["name"] != SIGNATURE):
        if asset["name"] in owned_names:
            github.delete_asset(asset["id"])
    github.upload(tag, paths)
    require_uploaded_assets(github.release(release_id), expected_sizes)
    # Validate the actual remote bytes before the signature makes the update visible to clients.
    with tempfile.TemporaryDirectory(prefix="ppp-release-verification-") as temporary:
        downloaded = Path(temporary)
        github.download(tag, list(expected_sizes), downloaded)
        shutil.copyfile(directory / SIGNATURE, downloaded / SIGNATURE)
        verify(downloaded)
    current = github.release(release_id)
    validate_release(current, release_id, tag)  # Respect a manual withdrawal while packages were uploading.
    validate_order(github.releases(), release_id, tag)
    require_uploaded_assets(current, expected_sizes)
    if ready_marker(current):
        raise ValueError("Another publisher sealed this release while the upload was running.")
    github.upload(tag, [directory / SIGNATURE])
    require_uploaded_assets(github.release(release_id), expected_sizes | {SIGNATURE: 64})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "publish"])
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    expected_commit = os.environ.get("GITHUB_SHA")
    if expected_commit:
        # Never sign a moved tag or silently build the latest main instead of the selected release commit.
        release_version(args.tag)
        actual = subprocess.check_output(["git", "rev-parse", f"refs/tags/{args.tag}^{{commit}}"], text=True).strip()
        if actual != expected_commit:
            raise ValueError("The release tag moved after this workflow started. Create a new version/tag.")
    github = GitHub(os.environ.get("GITHUB_REPOSITORY", "timbornemann/Password-Phrase-Producer"))
    if args.command == "prepare":
        outputs = prepare(github, args.release_id, args.tag, args.directory)
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for key, value in outputs.items():
                stream.write(f"{key}={value}\n")  # Values are validated numeric tags, never release-body text.
        print(f"Release {outputs['tag']}: build_needed={outputs['build_needed']}")
    else:
        publish(github, args.release_id, args.tag, args.directory)
        print(f"Release {args.tag}: all packages verified; update signature published last.")


if __name__ == "__main__":
    main()
