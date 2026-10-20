#!/usr/bin/env python3
"""Create/update a dedicated private build repository using existing Git auth.

Never stores/prints credentials. Uploads an EXE only after size/hash and remote
privacy checks. No game data enters Git history. Run with --help for operations.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OWNER = "lyszq"
MARKER = "Dedicated private native iOS build control for NFSU2Recomp"
EXPECTED_SHA = "8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297"


class GitHub:
    def __init__(self, repository):
        credential = subprocess.run(["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n", capture_output=True,
            text=True, cwd=ROOT, check=True)
        fields = dict(line.split("=", 1) for line in credential.stdout.splitlines() if "=" in line)
        self.token = fields["password"]
        self.repository = f"{OWNER}/{repository}"
        if self.api("/user")["login"] != OWNER:
            raise ValueError("Git credentials belong to another account")

    def api(self, path, method="GET", body=None, binary=None):
        # No caller-controlled service origin and no credential forwarding.
        origin = "https://uploads.github.com" if path.startswith("/upload/") else "https://api.github.com"
        if path.startswith("/upload/"): path = path[len("/upload"):]
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/vnd.github+json", "User-Agent": "NFSU2-private-build",
                   "X-GitHub-Api-Version": "2022-11-28"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if binary is not None:
            data = binary
            headers["Content-Type"] = "application/octet-stream"
        request = urllib.request.Request(origin + path, data=data, method=method, headers=headers)
        # All used endpoints return JSON/204 and should never redirect.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            content = response.read()
        return json.loads(content) if content else None

    def private(self):
        result = self.api("/repos/" + self.repository)
        if not result["private"] or result["owner"]["login"] != OWNER or result["description"] != MARKER:
            raise ValueError("refusing repository without the exact owner/privacy/purpose marker")
        return result

    def put_text(self, path, text):
        self.private()
        body = {"message": "Configure private native iOS build", "content": base64.b64encode(text.encode()).decode()}
        try:
            existing = self.api(f"/repos/{self.repository}/contents/{path}")
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
        else:
            if base64.b64decode(existing["content"]).decode() == text: return
            body["sha"] = existing["sha"]
        self.api(f"/repos/{self.repository}/contents/{path}", "PUT", body=body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default="NFSU2Recomp-ios-private")
    parser.add_argument("--create", action="store_true", help="create a new PRIVATE control repository if absent")
    parser.add_argument("--exe", type=Path, help="upload only the authenticated EXE as a PRIVATE release asset")
    parser.add_argument("--dispatch", action="store_true", help="start the configured private workflow")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.repository):
        raise ValueError("invalid repository name")
    # Validate confidential input BEFORE any remote mutation.
    blob = None
    if args.exe:
        blob = args.exe.read_bytes()
        if len(blob) != 4788224 or hashlib.sha256(blob).hexdigest() != EXPECTED_SHA:
            raise ValueError("unsupported EXE; no upload performed")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, cwd=ROOT).strip()
    client = GitHub(args.repository)
    if client.api("/repos/lyszq/NFSU2Recomp/commits/" + sha)["sha"] != sha:
        raise ValueError("source commit must be pushed to the public code repository first")
    try:
        client.private()
    except urllib.error.HTTPError as error:
        if error.code != 404 or not args.create: raise
        created = client.api("/user/repos", "POST", body={"name": args.repository,
            "description": MARKER, "private": True, "auto_init": False, "has_issues": False,
            "has_projects": False, "has_wiki": False})
        if not created["private"]: raise ValueError("private creation was not confirmed")
        client.private()
    template = (ROOT / "tools/ios_private/ios-private.yml").read_text()
    if template.count("SOURCE_COMMIT_PLACEHOLDER") != 1:
        raise ValueError("invalid workflow template")
    workflow = template.replace("SOURCE_COMMIT_PLACEHOLDER", sha)
    client.put_text(".github/workflows/ios-private.yml", workflow)
    client.put_text("README.md", "# Private NFSU2 iOS build control\n\n"
        "This repository must remain private. Do not fork or change visibility.\n"
        "Only orchestration is committed. The supported EXE is stored in a private release; "
        "lifted C is generated on the runner and never committed.\n\n"
        f"Pinned public source: `{sha}`. Run the manual Actions workflow to build.\n"
        "Artifacts contain game-derived executable code and must remain private.\n"
        "Unsigned IPA still requires signing. It tests one actual lifted function, not gameplay.\n")
    if blob is not None:
        client.private()
        try:
            release = client.api(f"/repos/{client.repository}/releases/tags/private-input-v1")
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
            release = client.api(f"/repos/{client.repository}/releases", "POST", body={
                "tag_name": "private-input-v1", "name": "Private supported executable input",
                "body": "Confidential build input. Keep this repository private.",
                "draft": False, "prerelease": True})
        assets = client.api(f"/repos/{client.repository}/releases/{release['id']}/assets")
        existing = next((a for a in assets if a["name"] == "SPEED2.EXE"), None)
        if existing:
            if existing["size"] != len(blob) or existing.get("digest") != "sha256:" + EXPECTED_SHA:
                raise ValueError("existing private input has no matching digest; preserved without overwrite")
        else:
            client.private()
            uploaded = client.api(f"/upload/repos/{client.repository}/releases/{release['id']}/assets?name=SPEED2.EXE",
                                  "POST", binary=blob)
            if uploaded["size"] != len(blob) or uploaded.get("digest") != "sha256:" + EXPECTED_SHA:
                raise ValueError("uploaded private input digest not confirmed")
    if args.dispatch:
        client.private()
        branch = client.private()["default_branch"]
        client.api(f"/repos/{client.repository}/actions/workflows/ios-private.yml/dispatches",
                   "POST", body={"ref": branch})
    print(json.dumps({"repository": client.repository, "private": client.private()["private"],
                      "source_sha": sha, "dispatched": args.dispatch,
                      "url": f"https://github.com/{client.repository}/actions"}, indent=2))


if __name__ == "__main__":
    main()
