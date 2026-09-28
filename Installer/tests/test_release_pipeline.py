import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_pipeline as pipeline


def release(tag="v2.6.0", release_id=1, **changes):
    return {"id": release_id, "tag_name": tag, "draft": False, "prerelease": False,
            "immutable": False, "body": "My release notes", "assets": [], **changes}


class FakeGitHub:
    def __init__(self):
        self.current = release()
        self.others = [release("v2.5.7", release_id=2)]
        self.content = {}
        self.events = []
        self.fail_upload = False
        self.corrupt_download = False
        self.withdraw_on_download = False

    def release(self, release_id):
        return copy.deepcopy(self.current)

    def releases(self):
        return [self.release(1), *self.others]

    def delete_asset(self, asset_id):
        self.events.append(("delete", asset_id))
        self.current["assets"] = [a for a in self.current["assets"] if a["id"] != asset_id]

    def upload(self, tag, paths):
        self.events.append(("upload", [p.name for p in paths]))
        for path in paths:
            self.content[path.name] = path.read_bytes()
            self.current["assets"].append({"name": path.name, "id": len(self.current["assets"]) + 10,
                                            "size": path.stat().st_size, "state": "uploaded"})
            if self.fail_upload:
                raise RuntimeError("Simulated connection failure")

    def download(self, tag, names, directory):
        self.events.append(("download", names))
        for name in names:
            data = self.content[name]
            (directory / name).write_bytes(b"corrupt" if self.corrupt_download and name.endswith(".apk") else data)
        if self.withdraw_on_download:
            self.current["prerelease"] = True


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ppp-release-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.github = FakeGitHub()
        artifacts = []
        for name in ("app-Setup.exe", "app-full.nupkg", "app.apk"):
            data = name.encode()
            (self.directory / name).write_bytes(data)
            artifacts.append({"fileName": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        (self.directory / pipeline.MANIFEST).write_text(json.dumps({"version": "2.6.0", "buildNumber": 2006000,
            "releaseTag": "v2.6.0", "artifacts": artifacts}), encoding="utf-8")
        (self.directory / pipeline.SIGNATURE).write_bytes(b"S" * 64)

    def verify(self, directory):
        # ECDSA itself is tested in .NET; this double asserts that remote bytes are checked before sealing.
        self.github.events.append(("verify", str(directory)))
        manifest = json.loads((directory / pipeline.MANIFEST).read_text())
        for artifact in manifest["artifacts"]:
            data = (directory / artifact["fileName"]).read_bytes()
            if len(data) != artifact["size"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                raise ValueError("Package verification failed")

    def publish(self):
        pipeline.publish(self.github, 1, "v2.6.0", self.directory, self.verify)

    def test_version_comes_only_from_tag(self):
        self.assertEqual(("2.6.0", 2006000), pipeline.release_version("v2.6.0"))
        self.assertEqual(pipeline.release_version("2.6.0"), pipeline.release_version("v2.6.0"))
        self.assertLess(pipeline.release_version("2.6.999")[1], pipeline.release_version("2.7.0")[1])
        self.assertLess(pipeline.release_version("2.999.999")[1], pipeline.release_version("3.0.0")[1])
        self.assertLessEqual(pipeline.release_version("2099.999.999")[1], 2100000000)

    def test_invalid_tags_cannot_become_versions_or_shell_arguments(self):
        for tag in ("2.6", "v2.6.0-beta.1", "v2.6.0+build", "02.6.0", "-2.6.0", "2.6.0\nbuild_needed=true",
                    "2.1000.0", "2100.0.0", "0.0.0", "../2.6.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                pipeline.release_version(tag)

    def test_prepare_preserves_notes_and_uses_chosen_version(self):
        outputs = pipeline.prepare(self.github, 1, "v2.6.0", self.directory)
        self.assertEqual("2.6.0", outputs["version"])
        self.assertEqual("2006000", outputs["build"])
        self.assertEqual("true", outputs["build_needed"])
        self.assertEqual("My release notes", (self.directory / "release-notes.md").read_text())
        self.assertEqual([], self.github.events)

    def test_drafts_prereleases_and_withdrawn_releases_cannot_build(self):
        for change in ({"draft": True}, {"prerelease": True}, {"tag_name": "v3.0.0"}, {"immutable": True}):
            self.github.current = release(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                pipeline.prepare(self.github, 1, "v2.6.0", self.directory)

    def test_duplicate_and_downgrade_versions_are_rejected(self):
        for tag in ("2.6.0", "v2.6.1", "v3.0.0"):
            self.github.others = [release(tag, release_id=2)]
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                pipeline.prepare(self.github, 1, "v2.6.0", self.directory)

    def test_newer_prerelease_does_not_block_stable_release(self):
        self.github.others = [release("v9.0.0", release_id=2, prerelease=True)]
        self.assertEqual("true", pipeline.prepare(self.github, 1, "v2.6.0", self.directory)["build_needed"])

    def test_legacy_published_assets_cannot_be_replaced_by_republishing_the_same_version(self):
        self.github.current["assets"] = [{"name": "Password-Phrase-Producer_2.6.0_SHA256.txt", "size": 10, "state": "uploaded"}]
        with self.assertRaises(ValueError):
            pipeline.prepare(self.github, 1, "v2.6.0", self.directory)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(any(e[0] in ("upload", "delete") for e in self.github.events))

    def test_signature_is_uploaded_only_after_remote_package_verification(self):
        self.publish()
        events = [event[0] for event in self.github.events]
        self.assertEqual(["verify", "upload", "download", "verify", "upload"], events)
        self.assertEqual([pipeline.SIGNATURE], self.github.events[-1][1])
        self.assertTrue(pipeline.ready_marker(self.github.current))

    def test_upload_failure_does_not_publish_ready_marker_and_can_be_retried(self):
        self.github.current["assets"] = [{"id": 99, "name": "user-notes.txt", "size": 10, "state": "uploaded"}]
        self.github.fail_upload = True
        with self.assertRaises(RuntimeError):
            self.publish()
        self.assertFalse(pipeline.ready_marker(self.github.current))
        self.github.fail_upload = False
        self.publish()
        self.assertTrue(pipeline.ready_marker(self.github.current))
        self.assertTrue(any(a["id"] == 99 for a in self.github.current["assets"]))

    def test_corrupt_remote_asset_never_receives_ready_marker(self):
        self.github.corrupt_download = True
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(pipeline.ready_marker(self.github.current))

    def test_sealed_release_is_never_overwritten_by_a_duplicate_event_or_rerun(self):
        self.publish()
        before = copy.deepcopy(self.github.content)
        self.github.events.clear()
        self.assertEqual("false", pipeline.prepare(self.github, 1, "v2.6.0", self.directory)["build_needed"])
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(before, self.github.content)
        self.assertFalse(any(e[0] in ("upload", "delete") for e in self.github.events))

    def test_manual_withdrawal_during_upload_is_respected(self):
        self.github.withdraw_on_download = True
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(pipeline.ready_marker(self.github.current))

    def test_manifest_from_another_build_cannot_be_published(self):
        path = self.directory / pipeline.MANIFEST
        manifest = json.loads(path.read_text())
        manifest["buildNumber"] = 999
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.publish()
        self.assertFalse(any(e[0] == "upload" for e in self.github.events))

    def test_incomplete_asset_state_is_not_ready_for_publication(self):
        current = release(assets=[{"name": "app.apk", "size": 10, "state": "starter"}])
        with self.assertRaises(ValueError):
            pipeline.require_uploaded_assets(current, {"app.apk": 10})


if __name__ == "__main__":
    unittest.main()
