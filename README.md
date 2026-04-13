# DataPrivacy.AI MCP Server

> **By [MEOK AI Labs](https://meok.ai)** — Sovereign AI tools for everyone.

GDPR and privacy compliance AI. Classify personal data, assess lawful basis for processing, generate DPIAs, check international data transfer legality, score breach severity, and generate Article 13/14 privacy notices.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/dataprivacy-ai)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `classify_personal_data` | Classify data fields as personal, special category, or anonymous |
| `assess_lawful_basis` | Determine appropriate lawful basis for processing personal data |
| `generate_dpia` | Generate a Data Protection Impact Assessment per GDPR Article 35 |
| `check_data_transfer` | Assess legality of international data transfers under GDPR |
| `calculate_breach_severity` | Score breach severity and determine ICO notification requirements |
| `generate_privacy_notice` | Generate an Article 13/14 compliant privacy notice |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/dataprivacy-ai-mcp.git
cd dataprivacy-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "dataprivacy-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/dataprivacy-ai-mcp"
    }
  }
}
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 50 requests/month |
| Pro | $19/mo | 5,000 requests/month |

[Get on MCPize](https://mcpize.com/mcp/dataprivacy-ai)

## Part of MEOK AI Labs

This is one of 255+ MCP servers by MEOK AI Labs. Browse all at [meok.ai](https://meok.ai) or [GitHub](https://github.com/CSOAI-ORG).

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | nicholas@meok.ai | United Kingdom
