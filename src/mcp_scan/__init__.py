"""
mcp-scan: a security scanner for Model Context Protocol servers.

Reads what an MCP server publishes (tools/list, resources/list, prompts/list)
and looks for signs of attack: tool poisoning, rug pull via description drift,
tool shadowing, secret harvesting, excessive filesystem and network
permissions, and hidden or encoded instructions.

Important: this scans CONFIGURATION, not runtime behaviour. See README ->
Limitations.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
