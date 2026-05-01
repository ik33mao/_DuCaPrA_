#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


GITHUB_API = "https://api.github.com"
DEFAULT_REPO = os.environ.get("DUCAPRA_GITHUB_REPO", "ik33mao/_DuCaPrA_")


def github_request(method: str, path: str, body: dict | None = None) -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ducapra-mcp",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read().decode()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as exc:
        message = exc.read().decode()
        raise RuntimeError(f"GitHub API error {exc.code}: {message}") from exc


def tool_repo_status(args: dict) -> dict:
    repo = args.get("repo", DEFAULT_REPO)
    data = github_request("GET", f"/repos/{repo}")
    return {
        "full_name": data["full_name"],
        "default_branch": data["default_branch"],
        "open_issues": data["open_issues_count"],
        "visibility": data["visibility"],
        "html_url": data["html_url"],
    }


def tool_list_issues(args: dict) -> dict:
    repo = args.get("repo", DEFAULT_REPO)
    state = args.get("state", "open")
    data = github_request("GET", f"/repos/{repo}/issues?state={state}")
    return {
        "issues": [
            {
                "number": issue["number"],
                "title": issue["title"],
                "state": issue["state"],
                "html_url": issue["html_url"],
            }
            for issue in data
            if "pull_request" not in issue
        ]
    }


def tool_create_issue(args: dict) -> dict:
    repo = args.get("repo", DEFAULT_REPO)
    issue = github_request(
        "POST",
        f"/repos/{repo}/issues",
        {
            "title": args["title"],
            "body": args.get("body", ""),
            "labels": args.get("labels", []),
        },
    )
    return {"number": issue["number"], "html_url": issue["html_url"]}


TOOLS = {
    "github_repo_status": {
        "description": "Return repository metadata for the configured GitHub repo.",
        "handler": tool_repo_status,
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
        },
    },
    "github_list_issues": {
        "description": "List GitHub issues for the configured repository.",
        "handler": tool_list_issues,
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "state": {"type": "string", "enum": ["open", "closed", "all"]},
            },
        },
    },
    "github_create_issue": {
        "description": "Create a GitHub issue in the configured repository.",
        "handler": tool_create_issue,
        "inputSchema": {
            "type": "object",
            "required": ["title"],
            "properties": {
                "repo": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
                "labels": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}


def respond(message_id: int | str | None, result: dict | None = None, error: dict | None = None) -> None:
    payload = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result or {}
    print(json.dumps(payload), flush=True)


def handle(message: dict) -> None:
    method = message.get("method")
    message_id = message.get("id")
    params = message.get("params", {})
    try:
        if method == "initialize":
            respond(
                message_id,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "ducapra-github-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            )
        elif method == "tools/list":
            respond(
                message_id,
                {
                    "tools": [
                        {
                            "name": name,
                            "description": spec["description"],
                            "inputSchema": spec["inputSchema"],
                        }
                        for name, spec in TOOLS.items()
                    ]
                },
            )
        elif method == "tools/call":
            name = params["name"]
            args = params.get("arguments", {})
            result = TOOLS[name]["handler"](args)
            respond(message_id, {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]})
        elif message_id is not None:
            respond(message_id, error={"code": -32601, "message": f"unknown method: {method}"})
    except Exception as exc:
        respond(message_id, error={"code": -32000, "message": str(exc)})


def main() -> None:
    for line in sys.stdin:
        if line.strip():
            handle(json.loads(line))


if __name__ == "__main__":
    main()
