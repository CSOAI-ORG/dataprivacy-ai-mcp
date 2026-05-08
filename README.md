<div align="center">

# Dataprivacy Ai MCP

**DataPrivacy.AI MCP Server - GDPR & Privacy Compliance**

[![PyPI](https://img.shields.io/pypi/v/meok-dataprivacy-ai-mcp)](https://pypi.org/project/meok-dataprivacy-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

DataPrivacy.AI MCP Server - GDPR & Privacy Compliance
Built by MEOK AI Labs | https://dataprivacyof.ai

GDPR personal data classification, lawful basis assessment, DPIA generation,
international data transfer checks, breach severity scoring, and privacy
notice generation. Covers UK GDPR and EU GDPR.

## Tools

| Tool | Description |
|------|-------------|
| `classify_personal_data` | Classify data fields as personal, special category, or anonymous per GDPR. |
| `assess_lawful_basis` | Determine appropriate lawful basis for processing personal data. |
| `generate_dpia` | Generate a Data Protection Impact Assessment template per GDPR Article 35. |
| `check_data_transfer` | Assess legality of international personal data transfers under GDPR Chapter V. |
| `calculate_breach_severity` | Score a data breach severity and determine ICO notification requirements. |
| `generate_privacy_notice` | Generate an Article 13/14 compliant privacy notice. |

## Installation

```bash
pip install meok-dataprivacy-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dataprivacy-ai": {
      "command": "python",
      "args": ["-m", "meok_dataprivacy_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
