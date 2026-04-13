# DataPrivacy.AI MCP Server

**GDPR & Privacy Compliance AI** | Built by [MEOK AI Labs](https://meok.ai)

MCP server for GDPR personal data classification, lawful basis assessment, DPIA generation, international data transfer checks, breach severity scoring, and privacy notice generation. Covers UK GDPR and EU GDPR.

## Tools

| Tool | Description |
|------|-------------|
| `classify_personal_data` | Classify data fields as personal/special category/anonymous per GDPR Art 4 & 9 |
| `assess_lawful_basis` | Determine appropriate lawful basis for processing per Article 6 |
| `generate_dpia` | Generate Data Protection Impact Assessment template per Article 35 |
| `check_data_transfer` | Assess legality of international transfers (adequacy, SCCs, BCRs) per Chapter V |
| `calculate_breach_severity` | Score breach severity and determine 72-hour ICO notification requirement |
| `generate_privacy_notice` | Generate Article 13/14 compliant privacy notice |

## Quick Start

```bash
pip install mcp
python server.py
```

## Configuration (Claude Desktop)

```json
{
  "mcpServers": {
    "dataprivacy-ai": {
      "command": "python",
      "args": ["/path/to/dataprivacy-ai-mcp/server.py"]
    }
  }
}
```

## Domain Knowledge

- GDPR Articles 4, 6, 9, 10, 13, 14, 33, 34, 35, 45, 46, 49
- UK Data Protection Act 2018
- ICO breach reporting requirements (72-hour rule)
- Adequacy decisions and EU-US Data Privacy Framework
- Standard Contractual Clauses (2021 SCCs)
- Legitimate Interests Assessment methodology
- Special category data conditions (Article 9(2))
- 60+ data field classifications

## License

MIT - see [LICENSE](LICENSE)

---

[dataprivacyof.ai](https://dataprivacyof.ai) | [MEOK AI Labs](https://meok.ai)
