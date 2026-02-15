"""
Good MCP server fixture — clean, well-behaved.

Tools: add_numbers, echo, reverse_string
No side effects, no exfiltration, no filesystem writes.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("test-good-server")


@mcp.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two numbers and return the result."""
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the provided message."""
    return message


@mcp.tool()
def reverse_string(text: str) -> str:
    """Reverse the input string."""
    return text[::-1]


if __name__ == "__main__":
    mcp.run(transport="stdio")
