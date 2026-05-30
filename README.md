# Agent Compliance Check

Automated compliance auditing for AI agent actions against regulatory, ethical, and internal safety standards.

## Overview

`agent-compliance-check` provides a robust engine for auditing agent activity logs. It identifies potential risks such as PII exposure, unauthorized tool usage, budget overruns, and access to restricted web domains.

## Features

- **PII Detection**: Automatically identifies emails, phone numbers, SSNs, and credit card patterns in agent inputs/outputs.
- **Tool Governance**: Enforces whitelists or blacklists for agent tool capabilities.
- **Budget Guardrails**: Monitors operation costs and flags agents exceeding assigned financial limits.
- **Domain Filtering**: Audits web navigation and search queries against restricted or malicious domains.
- **Extensible Architecture**: Easily add custom compliance rules by implementing the `Rule` interface.
- **Multi-format Reporting**: Generate reports in plain text, JSON, or Markdown.

## Installation

```bash
git clone https://github.com/Retsumdk/agent-compliance-check.git
cd agent-compliance-check
bun install
```

## Usage

### Initialize Configuration

Create a default configuration file (`compliance-config.json`):

```bash
bun run src/index.ts init
```

### Run an Audit

Audit an action log file:

```bash
bun run src/index.ts audit sample-actions.json
```

Generate a Markdown report:

```bash
bun run src/index.ts audit sample-actions.json --format markdown --output report.md
```

## Architecture

The system is built around three core components:

1. **Rule**: An interface for individual compliance checks.
2. **ComplianceEngine**: Orchestrates multiple rules and aggregates violations.
3. **ComplianceReporter**: Formats violation data for human or machine consumption.

## Configuration

Customize the audit behavior in `compliance-config.json`:

```json
{
  "forbiddenTools": ["delete_database", "wipe_disk", "uninstall_security"],
  "budgetCap": 50.0,
  "restrictedDomains": ["malicious-site.com", "darkweb-proxy.net"]
}
```

## Testing

Run the test suite using Bun:

```bash
bun test
```

## License

MIT License

---

Built by [Retsumdk](https://github.com/Retsumdk)
