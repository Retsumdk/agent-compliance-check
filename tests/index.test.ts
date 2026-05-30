import { describe, test, expect, beforeEach } from "bun:test";
import { 
  ComplianceEngine, 
  PIIRule, 
  ToolRestrictionRule, 
  BudgetRule, 
  DomainRule, 
  ComplianceReporter,
  Severity,
  Action
} from "../src/index";

describe("Agent Compliance Check", () => {
  let engine: ComplianceEngine;

  beforeEach(() => {
    engine = new ComplianceEngine();
  });

  test("PIIRule detects email and phone", async () => {
    const rule = new PIIRule();
    const action: Action = {
      id: "act-1",
      agentId: "agent-x",
      timestamp: new Date().toISOString(),
      tool: "send_email",
      input: { to: "user@example.com", text: "Call me at 555-0199" }
    };

    const violation = await rule.validate(action);
    expect(violation).not.toBeNull();
    expect(violation?.ruleId).toBe("pii-detection");
    expect(violation?.severity).toBe(Severity.HIGH);
  });

  test("ToolRestrictionRule blocks forbidden tools", async () => {
    const rule = new ToolRestrictionRule(["wipe_disk", "delete_user"]);
    const action: Action = {
      id: "act-2",
      agentId: "agent-x",
      timestamp: new Date().toISOString(),
      tool: "wipe_disk",
      input: { target: "/dev/sda" }
    };

    const violation = await rule.validate(action);
    expect(violation).not.toBeNull();
    expect(violation?.ruleId).toBe("tool-restriction");
    expect(violation?.severity).toBe(Severity.CRITICAL);
  });

  test("BudgetRule enforces cost cap", async () => {
    const rule = new BudgetRule(10.0);
    const actions: Action[] = [
      { id: "a1", agentId: "ax", timestamp: "t1", tool: "t", input: {}, metadata: { cost: 6.0 } },
      { id: "a2", agentId: "ax", timestamp: "t2", tool: "t", input: {}, metadata: { cost: 5.0 } }
    ];

    let v1 = await rule.validate(actions[0]);
    expect(v1).toBeNull();

    let v2 = await rule.validate(actions[1]);
    expect(v2).not.toBeNull();
    expect(v2?.message).toContain("Budget exceeded");
  });

  test("DomainRule blocks restricted URLs", async () => {
    const rule = new DomainRule(["malicious.com", "forbidden.net"]);
    const action: Action = {
      id: "act-3",
      agentId: "agent-x",
      timestamp: new Date().toISOString(),
      tool: "open_webpage",
      input: { url: "https://malicious.com/payload" }
    };

    const violation = await rule.validate(action);
    expect(violation).not.toBeNull();
    expect(violation?.ruleId).toBe("domain-restriction");
  });

  test("ComplianceEngine aggregates multiple violations", async () => {
    engine.addRule(new ToolRestrictionRule(["danger"]));
    engine.addRule(new PIIRule());

    const actions: Action[] = [
      { id: "1", agentId: "a", timestamp: "t", tool: "danger", input: {} },
      { id: "2", agentId: "a", timestamp: "t", tool: "safe", input: { email: "test@test.com" } }
    ];

    const violations = await engine.audit(actions);
    expect(violations.length).toBe(2);
    expect(violations.find(v => v.ruleId === "tool-restriction")).toBeDefined();
    expect(violations.find(v => v.ruleId === "pii-detection")).toBeDefined();
  });

  test("ComplianceEngine report format", async () => {
    engine.addRule(new ToolRestrictionRule(["danger"]));
    const actions: Action[] = [{ id: "1", agentId: "a", timestamp: "t", tool: "danger", input: {} }];
    await engine.audit(actions);

    const reporter = new ComplianceReporter(engine);
    const report = reporter.generate({ format: "text" });
    expect(report).toContain("Found 1 violations");
    expect(report).toContain("Usage of unauthorized tool: danger");
  });
});
