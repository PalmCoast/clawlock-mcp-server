# 🔒 Bot Lock — Identity & Security for AI Agents

**The MCP-native identity, credential vault, and audit layer every AI agent needs.**

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](https://spdx.org/licenses/BUSL-1.1.html)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-brightgreen.svg)](https://nodejs.org)

---

## The Problem

**218,000+ AI agents deployed. Zero have their own identity.**

- 53% of MCP servers use static API keys
- 79% pass credentials via plain environment variables
- 30% of live MCP servers have zero authentication
- GitHub, Smithery, and Asana MCP servers all compromised in 2025

Your agents run on **your** credentials. When they get compromised, **you** get compromised.

## The Solution

Bot Lock gives every AI agent its own cryptographic identity, encrypted credential vault, and immutable audit trail.

| Feature | What It Does |
|---|---|
| 🪪 Agent Identity | Ed25519 keypairs — every agent gets verifiable identity |
| 🔐 Credential Vault | AES-256-GCM encrypted — API keys never in plain text |
| 📊 Audit Ledger | Immutable log of every access and action |
| 🛡️ Scope Enforcement | Least-privilege — agents only access what they should |
| 🔄 Auto-Rotation | Credentials rotate on schedule (Pro+) |
| 🌐 Portable | Works with any MCP runtime |

## Quick Start

```bash
git clone https://github.com/PalmCoast/clawlock-mcp-server.git
cd clawlock-mcp-server
npm install
npm run build
npm start
```

### Claude Desktop

```json
{
  "mcpServers": {
    "clawlock": {
      "command": "node",
      "args": ["./dist/index.js"]
    }
  }
}
```

## 14 Tools

**Identity:** register_agent, get_agent, list_agents, suspend_agent, revoke_agent, check_scope
**Vault:** store_credential, use_credential, list_credentials, revoke_credential
**Audit:** get_audit_log
**System:** get_status, activate_license

## Pricing

- **48-hour trial** — 2 agents, full features
- **Starter $29/mo** — 5 agents
- **Pro $79/mo** — 25 agents, auto-rotation, team dashboard
- **Enterprise $249/mo** — Unlimited, SSO, SLA

Purchase at [clawlock-security.netlify.app](https://clawlock-security.netlify.app)

## Compatibility

Works with: OpenClaw, PicoClaw, ZeroClaw, IronClaw, TinyClaw, MimiClaw, Claude Desktop, any MCP stdio client.

## License

Business Source License 1.1 (BUSL-1.1)

Built by [AgentHive Inc.](https://agenthiveinc.com)

**Lock your bots.** 🔒