"""Tests for local Execution Graph generation."""
from __future__ import annotations

from xbom.analyzers.skillbom import build_execution_graph


def _node_ids(graph):
    return [n["id"] for n in graph["nodes"]]


def test_detects_tool_calls():
    content = "Use the Bash tool to run tests. Then use Read to check the file."
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "Bash" in ids
    assert "Read" in ids


def test_detects_shell_commands():
    content = "Run `curl https://api.example.com` and `npm install express`"
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "curl" in ids
    assert "npm" in ids


def test_detects_network_targets():
    content = "Fetch data from https://api.openai.com/v1/chat and https://hooks.slack.com/trigger"
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "api.openai.com" in ids
    assert "hooks.slack.com" in ids


def test_detects_file_access():
    content = "Read ~/.ssh/id_rsa and write to /etc/hosts"
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "~/.ssh/id_rsa" in ids
    assert "/etc/hosts" in ids


def test_detects_skill_calls():
    content = 'Use skill: "deploy-helper" and invoke /commit'
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "skill:deploy-helper" in ids
    assert "skill:/commit" in ids


def test_detects_mcp_calls():
    content = "Call mcp__slack__send_message and mcp__github__create_pr"
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "mcp:slack:send_message" in ids
    assert "mcp:github:create_pr" in ids


def test_detects_env_access():
    content = "Use $API_KEY and read process.env.SECRET_TOKEN"
    graph = build_execution_graph(content, "test-skill")
    ids = _node_ids(graph)
    assert "env:API_KEY" in ids
    assert "env:SECRET_TOKEN" in ids


def test_edges_connect_skill_to_nodes():
    content = "Use Bash to run curl https://api.example.com"
    graph = build_execution_graph(content, "my-skill")
    edges = graph["edges"]
    tool_edges = [e for e in edges if e["from"] == "skill:my-skill"]
    assert len(tool_edges) > 0


def test_empty_content():
    graph = build_execution_graph("", "empty")
    assert graph["nodes"] == []
    assert graph["edges"] == []


def test_ignores_cdn_domains():
    content = "Load https://cdn.tailwindcss.com and https://fonts.googleapis.com/css"
    graph = build_execution_graph(content, "test")
    ids = _node_ids(graph)
    assert "cdn.tailwindcss.com" not in ids
    assert "fonts.googleapis.com" not in ids
