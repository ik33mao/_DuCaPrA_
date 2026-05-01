# GitHub MCP Server

This repo includes a minimal stdio MCP server for managing the GitHub repository through the GitHub REST API.

## Tools

- `github_repo_status`
- `github_list_issues`
- `github_create_issue`

## Configuration

Set a fine-grained GitHub token with only the permissions needed by the tools you enable:

```bash
export GITHUB_TOKEN=github_pat_...
export DUCAPRA_GITHUB_REPO=ik33mao/_DuCaPrA_
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "ducapra-github": {
      "command": "python3",
      "args": ["/absolute/path/to/tools/github_mcp_server.py"],
      "env": {
        "GITHUB_TOKEN": "github_pat_...",
        "DUCAPRA_GITHUB_REPO": "ik33mao/_DuCaPrA_"
      }
    }
  }
}
```

Do not commit tokens. Use read-only tokens for status/listing and issue-write tokens only when creating issues.
