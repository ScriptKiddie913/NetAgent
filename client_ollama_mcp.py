"""
Backward-compatible entry point for the old single-agent chat client.
Equivalent to: `wireshark-agent chat --single`

New setups should use the CLI directly, which also gives you the multi-agent
supervisor mode: `wireshark-agent chat`.
"""
import sys

from wireshark_mcp.cli import cli

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "chat", "--single"] + sys.argv[1:]
    cli(obj={})
