"""No credentials or game data: test disclosure boundaries with hostile fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import public_private_build as build


def context():
    return {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": build.PUBLIC,
            "GITHUB_REF": "refs/heads/" + build.BRANCH, "GITHUB_EVENT_NAME": "push",
            "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
            "GITHUB_WORKFLOW_REF": build.PUBLIC + "/.github/workflows/ios-private-io.yml@refs/heads/" + build.BRANCH,
            "GITHUB_SHA": "a" * 40, "SOURCE_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}


def policy():
    return {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
            "protection_rules": [{"type": "required_reviewers", "reviewers": [
                {"type": "User", "reviewer": {"login": "lyszq"}}]}]}


class Boundaries(unittest.TestCase):
    def test_forks_prs_untrusted_refs_and_debug_fail_closed(self):
        build.validate_context(context())
        for key, value in [("GITHUB_REPOSITORY", "attacker/fork"), ("GITHUB_EVENT_NAME", "pull_request_target"),
                           ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "workflow_run"),
                           ("GITHUB_REF", "refs/pull/1/merge"), ("SOURCE_SHA", "main"),
                           ("GITHUB_SHA", "b" * 40), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("ACTIONS_STEP_DEBUG", "true"), ("RUNNER_DEBUG", "1"),
                           ("GITHUB_WORKFLOW_REF", "attacker@main")]:
            with self.subTest(key=key, value=value), self.assertRaises(build.ClosedError):
                build.validate_context(dict(context(), **{key: value}))

    def test_environment_owner_review_and_exact_branch_required(self):
        branches = {"branch_policies": [{"name": build.BRANCH, "type": "branch"}]}
        build.validate_policy(policy(), branches)
        for bad in ({"branch_policies": []}, {"branch_policies": [{"name": "*", "type": "branch"}]},
                    {"branch_policies": [{"name": build.BRANCH, "type": "tag"}]}):
            with self.assertRaises(build.ClosedError):
                build.validate_policy(policy(), bad)
        with self.assertRaises(build.ClosedError):
            build.validate_policy(dict(policy(), protection_rules=[]), branches)

    def test_child_has_no_secrets_action_channels_or_startup_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            env = build.child_environment({"PATH": os.environ["PATH"], "PRIVATE_IOS_TOKEN": "canary",
                "GITHUB_TOKEN": "canary", "ACTIONS_RUNTIME_TOKEN": "canary", "ACTIONS_CACHE_URL": "canary",
                "GITHUB_ENV": "canary", "GITHUB_OUTPUT": "canary", "GITHUB_STEP_SUMMARY": "canary",
                "BASH_ENV": "canary", "PYTHONPATH": "canary", "GH_TOKEN": "canary"}, Path(temp))
            self.assertNotIn("canary", env.values())
            self.assertEqual(env["HOME"], str(Path(temp) / "home"))

    def test_subprocess_output_and_workflow_commands_are_private(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            runner = build.Builder(work, dict(os.environ))
            runner.source = work
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                runner.run([sys.executable, "-c", "import sys; print('SECRET-CANARY ::error::hostile'); sys.stderr.write('PRIVATE-CODE')"])
            self.assertEqual(out.getvalue(), "")
            self.assertIn("SECRET-CANARY", (runner.evidence / "build.log").read_text())
            self.assertIn("PRIVATE-CODE", (runner.evidence / "build.log").read_text())

    def test_exception_values_never_reach_public_log(self):
        out = io.StringIO()
        with patch.dict(os.environ, context(), clear=True), patch.object(build, "public_json", side_effect=RuntimeError("TOKEN-CANARY ::warning::private C")), contextlib.redirect_stdout(out):
            self.assertEqual(build.main(), 1)
        self.assertNotIn("CANARY", out.getvalue())
        self.assertNotIn("::warning", out.getvalue())

    def test_private_identity_and_visibility_are_strict(self):
        client = build.PrivateIO("test-token")
        valid = {"private": True, "id": build.PRIVATE_ID, "full_name": build.PRIVATE, "description": build.MARKER}
        with patch.object(client, "request", return_value=valid):
            self.assertEqual(client.private(), valid)
        for key, value in [("private", False), ("id", 1), ("full_name", build.PUBLIC), ("description", "wrong")]:
            with patch.object(client, "request", return_value=dict(valid, **{key: value})), self.assertRaises(build.ClosedError):
                client.private()

    def test_upload_checks_privacy_before_sending_bytes(self):
        client = build.PrivateIO("test-token")
        with patch.object(client, "private", side_effect=build.ClosedError), patch.object(client, "request") as request:
            with self.assertRaises(build.ClosedError):
                client.upload(123, Path("absent.ipa"))
            request.assert_not_called()

    def test_input_metadata_rejected_before_download(self):
        client = build.PrivateIO("test-token")
        with patch.object(client, "private"), patch.object(client, "request", side_effect=[{"id": 1},
                    [{"name": "SPEED2.EXE", "id": 2, "size": 5, "digest": "sha256:wrong"}]]) as request:
            with self.assertRaises(build.ClosedError):
                client.input(Path("must-not-write.exe"))
            self.assertEqual(request.call_count, 2)

    def test_download_redirect_does_not_forward_private_authorization(self):
        client = build.PrivateIO("test-token")
        location = "https://release-assets.githubusercontent.com/example?private-signature=fixture"
        redirect = urllib.error.HTTPError("https://api.github.com", 302, "Found", {"Location": location}, None)
        response = io.BytesIO(b"synthetic bytes")
        with patch.object(client.opener, "open", side_effect=[redirect, response]) as opened:
            self.assertEqual(client.request("/repos/" + build.PRIVATE + "/releases/assets/1", raw=True), b"synthetic bytes")
        self.assertIn("Authorization", opened.call_args_list[0].args[0].headers)
        self.assertNotIn("Authorization", opened.call_args_list[1].args[0].headers)

    def test_download_refuses_external_redirect_and_cross_repo_requests(self):
        client = build.PrivateIO("test-token")
        for location in ("http://release-assets.githubusercontent.com/x", "https://evil.example/x",
                         "https://release-assets.githubusercontent.com.evil.example/x", "https://user@release-assets.githubusercontent.com/x"):
            with patch.object(client.opener, "open", side_effect=urllib.error.HTTPError("url", 302, "Found", {"Location": location}, None)), self.assertRaises(build.ClosedError):
                client.request("/repos/" + build.PRIVATE + "/releases/assets/1", raw=True)
        with self.assertRaises(build.ClosedError):
            client.request("/repos/" + build.PUBLIC + "/releases", "POST", body={})
        with self.assertRaises(build.ClosedError):
            client.request("/repos/" + build.PRIVATE + "-spoof/releases", "POST", body={})

    def exercise_main(self, fail_compile=False, fail_upload=False):
        """Drive the real orchestration with synthetic private files, not a game."""
        uploads = []
        secrets = []
        class FakeIO:
            def __init__(self, token):
                secrets.append(token)
            def begin(self, *args):
                return {"id": 99}
            def input(self, dest):
                dest.write_text("PRIVATE-INPUT-CANARY")
                return {"sha256": "fixture"}
            def upload(self, rid, path):
                self_test.assertEqual(rid, 99)
                if fail_upload:
                    raise RuntimeError("TOKEN-CANARY private response")
                uploads.append((path.name, path.read_bytes()))
                return {"id": len(uploads), "sha256": build.sha256(path), "name": path.name}
        class FakeBuilder(build.Builder):
            def build(self, source):
                self.source.mkdir()
                (self.evidence / "build.log").write_text("PRIVATE-COMPILER-CANARY ::error::do not execute")
                self_test.assertNotIn("PRIVATE_IOS_TOKEN", self.env)
                self_test.assertNotIn("GITHUB_OUTPUT", self.env)
                return "fixture-python"
            def compile(self, *args):
                (self.source / "generated.c").write_text("PRIVATE-C-CANARY")
                if fail_compile:
                    raise RuntimeError("PRIVATE-EXCEPTION-CANARY")
                ipa = self.work / build.IPA
                ipa.write_bytes(b"SYNTHETIC-VERIFIED-IPA")
                return ipa
        self_test = self
        with tempfile.TemporaryDirectory() as temp:
            env = dict(context(), RUNNER_TEMP=temp, PATH=os.environ["PATH"], PRIVATE_IOS_TOKEN="TOKEN-CANARY", GITHUB_OUTPUT="/must-not-write")
            out = io.StringIO()
            def public(path):
                return policy() if "branch-policies" not in path else {"branch_policies": [{"name": build.BRANCH, "type": "branch"}]}
            with patch.dict(os.environ, env, clear=True), patch.object(build, "public_json", side_effect=public), patch.object(build, "PrivateIO", FakeIO), patch.object(build, "Builder", FakeBuilder), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = build.main()
            self.assertEqual(list(Path(temp).iterdir()), [])
        self.assertEqual(secrets, ["TOKEN-CANARY"])
        self.assertNotIn("CANARY", out.getvalue())
        self.assertNotIn("::error", out.getvalue())
        return code, uploads

    def test_success_requires_private_ipa_diagnostics_receipt_and_cleanup(self):
        code, uploads = self.exercise_main()
        self.assertEqual(code, 0)
        self.assertEqual([x[0] for x in uploads], [build.IPA, "private-diagnostics.tar.gz", "receipt.json"])
        receipt = json.loads(uploads[-1][1])
        self.assertTrue(receipt["complete"])
        self.assertEqual((receipt["source_sha"], receipt["run_id"], receipt["run_attempt"]), ("a" * 40, 123, 1))

    def test_compile_failure_sends_no_ipa_and_cleans_private_bytes(self):
        code, uploads = self.exercise_main(fail_compile=True)
        self.assertEqual(code, 1)
        self.assertEqual([x[0] for x in uploads], ["private-diagnostics.tar.gz", "receipt.json"])
        receipt = json.loads(uploads[-1][1])
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["error_type"], "RuntimeError")

    def test_private_upload_failure_has_no_public_fallback(self):
        code, uploads = self.exercise_main(fail_upload=True)
        self.assertEqual(code, 1)
        self.assertEqual(uploads, [])


if __name__ == "__main__":
    unittest.main()
