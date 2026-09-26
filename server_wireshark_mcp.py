"""
Backward-compatible entry point. If you had an MCP client (e.g. Claude Desktop)
configured to run `python server_wireshark_mcp.py`, this keeps working — it just
delegates to the real, expanded server in wireshark_mcp/server.py.

New setups should point at `python -m wireshark_mcp.server` (or use the CLI:
`wireshark-agent server`) instead.
"""
from wireshark_mcp.server import mcp

if __name__ == "__main__":
    mcp.run()
