/**
 * Agent Compliance Check
 * Automated compliance auditing for agent actions against regulatory or internal safety standards.
 * Built by Retsumdk
 */

import { Command } from "commander";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

// --- Types & Interfaces ---

export enum Severity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export interface Action {
  id: string;
  agentId: string;
  timestamp: string;
  tool: string;
  input: any;
  output?: any;
  metadata?: Record<string, any>;
}

export interface ComplianceViolation {
  actionId: string;
  ruleId: string;
  severity: Severity;
  message: string;
  timestamp: string;
  remediation?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  validate(action: Action): Promise<ComplianceViolation | null>;
}

// --- Built-in Rules ---

/**
 * PII Detection Rule
 * Checks action inputs and outputs for sensitive information.
 */
export class PIIRule implements Rule {
  id = "pii-detection";
  name = "PII Detection";
  description = "Detects personally identifiable information in agent data.";
  severity = Severity.HIGH;

  private patterns = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone: /(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    creditCard: /\b(?:\d[ -]*?){13,16}\b/g,
  };

  async validate(action: Action): Promise<ComplianceViolation | null> {
    const dataString = JSON.stringify({ input: action.input, output: action.output });
    
    for (const [type, pattern] of Object.entries(this.patterns)) {
      if (pattern.test(dataString)) {
        return {
          actionId: action.id,
          ruleId: this.id,
          severity: this.severity,
          message: `Detected potential ${type} in action data.`,
          timestamp: new Date().toISOString(),
          remediation: "Sanitize the data before passing it to the agent.",
        };
      }
    }
    return null;
  }
}

/**
 * Tool Restriction Rule
 * Enforces a whitelist or blacklist of allowed tools.
 */
export class ToolRestrictionRule implements Rule {
  id = "tool-restriction";
  name = "Tool Restriction";
  description = "Prevents usage of unauthorized or dangerous tools.";
  severity = Severity.CRITICAL;

  constructor(private forbiddenTools: string[]) {}

  async validate(action: Action): Promise<ComplianceViolation | null> {
    if (this.forbiddenTools.includes(action.tool)) {
      return {
        actionId: action.id,
        ruleId: this.id,
        severity: this.severity,
        message: `Usage of unauthorized tool: ${action.tool}`,
        timestamp: new Date().toISOString(),
        remediation: "Update agent policy to remove this tool from the capability list.",
      };
    }
    return null;
  }
}

/**
 * Budget Enforcement Rule
 * Monitors and limits agent spending.
 */
export class BudgetRule implements Rule {
  id = "budget-enforcement";
  name = "Budget Enforcement";
  description = "Limits agent operations based on cost thresholds.";
  severity = Severity.MEDIUM;

  private currentTotal = 0;

  constructor(private budgetCap: number) {}

  async validate(action: Action): Promise<ComplianceViolation | null> {
    const cost = action.metadata?.cost || 0;
    this.currentTotal += cost;

    if (this.currentTotal > this.budgetCap) {
      return {
        actionId: action.id,
        ruleId: this.id,
        severity: this.severity,
        message: `Budget exceeded: ${this.currentTotal.toFixed(2)} > ${this.budgetCap.toFixed(2)}`,
        timestamp: new Date().toISOString(),
        remediation: "Pause agent or increase budget allocation.",
      };
    }
    return null;
  }
}

/**
 * Domain Restriction Rule
 * Checks web browsing against restricted domains.
 */
export class DomainRule implements Rule {
  id = "domain-restriction";
  name = "Domain Restriction";
  description = "Prevents agents from accessing restricted web domains.";
  severity = Severity.HIGH;

  constructor(private restrictedDomains: string[]) {}

  async validate(action: Action): Promise<ComplianceViolation | null> {
    if (action.tool === "web_search" || action.tool === "open_webpage") {
      const url = action.input?.url || action.input?.query || "";
      for (const domain of this.restrictedDomains) {
        if (url.includes(domain)) {
          return {
            actionId: action.id,
            ruleId: this.id,
            severity: this.severity,
            message: `Restricted domain accessed: ${domain}`,
            timestamp: new Date().toISOString(),
            remediation: "Blacklist the domain in the network proxy or agent settings.",
          };
        }
      }
    }
    return null;
  }
}

// --- Engine ---

export class ComplianceEngine {
  private rules: Rule[] = [];
  private violations: ComplianceViolation[] = [];

  addRule(rule: Rule) {
    this.rules.push(rule);
  }

  async audit(actions: Action[]): Promise<ComplianceViolation[]> {
    for (const action of actions) {
      for (const rule of this.rules) {
        const violation = await rule.validate(action);
        if (violation) {
          this.violations.push(violation);
        }
      }
    }
    return this.violations;
  }

  getViolationsBySeverity(severity: Severity): ComplianceViolation[] {
    return this.violations.filter(v => v.severity === severity);
  }

  getViolations(): ComplianceViolation[] {
    return this.violations;
  }

  clearViolations() {
    this.violations = [];
  }
}

// --- Reporters ---

export interface ReportOptions {
  format: "text" | "json" | "markdown";
}

export class ComplianceReporter {
  constructor(private engine: ComplianceEngine) {}

  generate(options: ReportOptions): string {
    const violations = this.engine.getViolations();
    
    if (options.format === "json") {
      return JSON.stringify(violations, null, 2);
    }

    if (options.format === "markdown") {
      return this.generateMarkdown(violations);
    }

    return this.generateText(violations);
  }

  private generateText(violations: ComplianceViolation[]): string {
    if (violations.length === 0) return "✅ No compliance violations detected.";
    
    let out = `⚠️ Found ${violations.length} violations:\n`;
    for (const v of violations) {
      out += `\n[${v.severity}] ${v.ruleId}: ${v.message}\n`;
      out += `  Action ID: ${v.actionId}\n`;
      out += `  Timestamp: ${v.timestamp}\n`;
      if (v.remediation) out += `  Remediation: ${v.remediation}\n`;
    }
    return out;
  }

  private generateMarkdown(violations: ComplianceViolation[]): string {
    if (violations.length === 0) return "# Compliance Report\n\n✅ No compliance violations detected.";

    let md = "# Agent Compliance Report\n\n";
    md += `**Total Violations:** ${violations.length}\n\n`;
    
    md += "| Severity | Rule | Message | Action ID | Timestamp |\n";
    md += "|----------|------|---------|-----------|-----------|\n";
    
    for (const v of violations) {
      md += `| ${v.severity} | ${v.ruleId} | ${v.message} | \`${v.actionId}\` | ${v.timestamp} |\n`;
    }

    md += "\n## Remediation Steps\n\n";
    const uniqueRules = [...new Set(violations.map(v => v.ruleId))];
    for (const ruleId of uniqueRules) {
      const v = violations.find(v => v.ruleId === ruleId);
      if (v?.remediation) {
        md += `### ${ruleId}\n- ${v.remediation}\n\n`;
      }
    }
    
    return md;
  }
}

// --- CLI ---

const program = new Command();

program
  .name("agent-compliance-check")
  .description("Automated compliance auditing for agent actions")
  .version("1.0.0");

program
  .command("audit")
  .description("Audit a log of agent actions")
  .argument("<file>", "Path to action log file (JSON)")
  .option("-c, --config <path>", "Config file path", "compliance-config.json")
  .option("-f, --format <type>", "Report format (text, json, markdown)", "text")
  .option("-o, --output <path>", "Output file path")
  .action(async (file, options) => {
    try {
      const data = readFileSync(file, "utf-8");
      const actions: Action[] = JSON.parse(data);

      const engine = new ComplianceEngine();
      
      // Load rules from config or use defaults
      let config = {
        forbiddenTools: ["delete_database", "wipe_disk"],
        budgetCap: 100.0,
        restrictedDomains: ["malicious-site.com", "forbidden-data.io"],
      };

      if (existsSync(options.config)) {
        config = { ...config, ...JSON.parse(readFileSync(options.config, "utf-8")) };
      }

      engine.addRule(new PIIRule());
      engine.addRule(new ToolRestrictionRule(config.forbiddenTools));
      engine.addRule(new BudgetRule(config.budgetCap));
      engine.addRule(new DomainRule(config.restrictedDomains));

      console.log(`Auditing ${actions.length} actions...`);
      const violations = await engine.audit(actions);
      
      const reporter = new ComplianceReporter(engine);
      const report = reporter.generate({ format: options.format as any });
      
      if (options.output) {
        writeFileSync(options.output, report);
        console.log(`✓ Report saved to ${options.output}`);
      } else {
        console.log(report);
      }
      
      if (violations.some(v => v.severity === Severity.CRITICAL || v.severity === Severity.HIGH)) {
        console.error("\n❌ Critical compliance failures detected.");
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(1);
    }
  });

program
  .command("init")
  .description("Initialize a default compliance configuration")
  .action(() => {
    const config = {
      forbiddenTools: ["delete_database", "wipe_disk", "uninstall_security"],
      budgetCap: 50.0,
      restrictedDomains: ["malicious-site.com", "darkweb-proxy.net"],
    };
    writeFileSync("compliance-config.json", JSON.stringify(config, null, 2));
    console.log("✓ Created compliance-config.json");
  });

if (import.meta.main) {
  program.parse(process.argv);
}
