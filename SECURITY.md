# Security policy

## Reporting a vulnerability

Please report it privately through GitHub:
**[Report a vulnerability](https://github.com/dannyleb/network-sentinel-mcp/security/advisories/new)**.
Don't open a public issue.

Include the version (`network-sentinel-mcp -version`), your operating system, steps to reproduce or a proof of
concept, and what an attacker could do with it.

This is a one-person project, so reports are handled on a best-effort basis. Fixes ship in a new release, and the
advisory credits you unless you'd rather not be named.

## Supported versions

Only the latest release gets security fixes.

## What counts as a vulnerability

This server makes a few promises. Anything that breaks one of them is in scope:

- **It changes nothing.** No tool or resource modifies Network Sentinel's data or configuration, or writes to disk.
- **It stays on this machine.** It connects only to loopback addresses, and the only request it sends is
  `GET /api/snapshot`.
- **The token stays secret.** The dashboard login token never appears in tool output, logs or error messages.
- **Network text is cleaned.** Host names, DNS names and alert details reach the AI client without control,
  direction-changing or invisible characters, and with bounded length.
- **Input is bounded.** Every argument is validated, and no input can crash the server or make it read without
  limit.

## Out of scope

- **Vulnerabilities in Network Sentinel itself.** Report those to
  [Network Sentinel's repository](https://github.com/dannyleb/network-sentinel).
- **Tool results reaching your AI client's model provider.** That's how MCP works; the README's
  [What leaves your machine](README.md#what-leaves-your-machine) section explains it.
- **Prompt injection in ordinary text.** A remote server can choose a host name made of plain words. This server
  labels network text as data and tells the model so, but it can't stop a model from being persuaded by it.
- **Attacks that need code already running on your machine as you**, such as a process listening on Network
  Sentinel's port in its place.
