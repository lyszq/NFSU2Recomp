#!/usr/bin/env python3
"""Local-only environment setup; NEVER stores existing Git auth in Actions.

The owner creates a separately scoped fine-grained PAT in GitHub's secure UI.
This helper configures environment metadata using existing local Git auth.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
import urllib.error

from provision import GitHub
from public_private_build import BRANCH, ENVIRONMENT, PRIVATE, PRIVATE_ID, PUBLIC, validate_policy

BASE = "/repos/" + PUBLIC
ENV = BASE + "/environments/" + ENVIRONMENT


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--configure", action="store_true", help="create missing owner-reviewed environment and exact branch policy")
    p.add_argument("--enable", action="store_true", help="enable after the scoped environment secret has been entered manually")
    p.add_argument("--request", action="store_true", help="queue a feature-branch build by changing the public request file")
    args = p.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise ValueError("local setup only; never expose developer credentials to a runner")
    client = GitHub("NFSU2Recomp-ios-private")
    if client.private()["id"] != PRIVATE_ID or client.repository != PRIVATE:
        raise ValueError("unexpected private repository")
    repo = client.api(BASE)
    if repo["private"] or repo["full_name"] != PUBLIC or repo["id"] != 1426968128:
        raise ValueError("unexpected public repository")
    try:
        environment = client.api(ENV)
    except urllib.error.HTTPError as error:
        if error.code != 404 or not args.configure:
            raise
        owner = client.api("/users/lyszq")
        environment = client.api(ENV, "PUT", body={"wait_timer": 0, "prevent_self_review": False,
            "reviewers": [{"type": "User", "id": owner["id"]}],
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}})
    policies = client.api(ENV + "/deployment-branch-policies?per_page=100")
    if args.configure and not policies["branch_policies"]:
        client.api(ENV + "/deployment-branch-policies", "POST", body={"name": BRANCH, "type": "branch"})
        policies = client.api(ENV + "/deployment-branch-policies?per_page=100")
    validate_policy(environment, policies)
    secrets = client.api(ENV + "/secrets")
    ready = "PRIVATE_IOS_TOKEN" in {s["name"] for s in secrets["secrets"]}
    # A repository-level secret defeats the intended environment-only placement.
    repository_secrets = client.api(BASE + "/actions/secrets")
    if "PRIVATE_IOS_TOKEN" in {s["name"] for s in repository_secrets["secrets"]}:
        raise ValueError("move PRIVATE_IOS_TOKEN from repository secrets to the protected environment")
    if args.enable or args.request:
        if not ready:
            raise ValueError("enter the separate private-repo-only token in the protected environment first")
        try:
            variable = client.api(BASE + "/actions/variables/PRIVATE_IOS_ENABLED")
        except urllib.error.HTTPError as error:
            if error.code != 404 or not args.enable:
                raise
            client.api(BASE + "/actions/variables", "POST", body={"name": "PRIVATE_IOS_ENABLED", "value": "true"})
        else:
            if variable["value"] != "true":
                if not args.enable:
                    raise ValueError("enable the lane first")
                client.api(BASE + "/actions/variables/PRIVATE_IOS_ENABLED", "PATCH", body={"name": "PRIVATE_IOS_ENABLED", "value": "true"})
    if args.request:
        path = BASE + "/contents/.github/private-ios-request.txt"
        previous = client.api(path + "?ref=" + BRANCH)
        text = "Public runner / private IO request " + datetime.now(timezone.utc).isoformat() + "\nOwner-reviewed environment required.\n"
        client.api(path, "PUT", body={"message": "Request private IO full ARM64 IPA build", "branch": BRANCH,
            "sha": previous["sha"], "content": base64.b64encode(text.encode()).decode()})
    print(json.dumps({"environment": ENVIRONMENT, "branch": BRANCH, "owner_review_required": True,
        "private": True, "scoped_secret_present": ready, "enabled_now": args.enable, "requested": args.request}, indent=2))


if __name__ == "__main__":
    main()
