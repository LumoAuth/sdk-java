# LumoAuth Java SDK v1.4.0 (`java-v1.4.0`)

**Release Date:** November 6, 2026  
**Tag:** `java-v1.4.0`

## Packages Updated

| Package | Version |
| :--- | :--- |
| `io.lumoauth:lumo-auth-parent` | `1.4.0` |
| `io.lumoauth:lumo-auth-java` | `1.4.0` |
| `io.lumoauth:lumo-auth-spring-boot-starter` | `1.4.0` |

---

## Highlights & New Features

### 1. Token and Cost Usage Reporting (`io.lumoauth:lumo-auth-java`)

LumoAuth does not see an agent's model calls. Agents can now report the tokens and cost of their model calls, so that the token and cost limits of the agent's budget (`max_tokens_per_hour`, `max_tokens_per_day`, `max_cost_per_day_usd`, `max_cost_per_month_usd`) count real usage.

- Added `AgentsResource.reportUsage(long tokens, double costUsd)` (`io.lumoauth.resources.AgentsResource`). It sends `{"tokens", "cost_usd"}` to `POST /orgs/{orgId}/api/v1/agents/me/usage`, registered as the new `Routes.AGENTS_REPORT_USAGE` route (`agents.reportUsage`) in `io.lumoauth.Routes`.
- Added `LumoAgent.reportUsage(long tokens, double costUsd)` (`io.lumoauth.LumoAgent`). The budget in the result replaces the cached budget, so `checkBudget()` reflects the report without another request.
- Added `UserInfo.withBudgetPolicy(AgentBudget)`, which returns a copy of the `UserInfo` with another budget.
- The SDK checks the report before it sends a request. It throws `LumoAuthValidationException` in these cases:
  - `tokens` is negative.
  - `costUsd` is negative, `NaN` or infinite.
  - Both values are zero.
- Added the `io.lumoauth.model.UsageReportResult` record:
  - `recorded()` returns a `UsageReportResult.Recorded` with `tokens()` and `costUsd()`: the tokens and cost that the server added.
  - `budget()` returns the agent's budget after the report, in the same shape as `budgetPolicy()` in `UserInfo`. When `budget().exhausted()` is true, the next metered call (Ask API call, token request or JIT request) gets HTTP 429.
  - `raw()` returns the complete decoded response.
- A report is not a metered call. The server accepts it even when the budget is spent.
- Only agent credentials can report usage. A `LumoAuth` client also has `agents().reportUsage(...)`, but the server answers other tokens and portal test tokens with 403.
- The server limits how often each agent can report (429 `rate_limited`). If your agent calls models often, send fewer, larger reports.

```java
ChatResponse response = llm.chat(request);

agent.reportUsage(response.usage().totalTokens(), 0.0042);

// Uses the budget from the report; no extra request.
// Throws LumoAuthBudgetExceededException when the next Ask, token or JIT request would get 429.
agent.checkBudget();
```

### 2. Capability Matching Like the Server (`io.lumoauth.Capabilities`)

Capability checks in the SDK compared strings with `equals`, so they could disagree with the server. The server stores `tool:search_web` as `tool.search_web`, and a held `invoices.*` covers `invoices.read`. The SDK now uses the server's rules.

- Added the `io.lumoauth.Capabilities` class:
  - `Capabilities.normalize(capability)` returns the stored form. It trims the name, lower-cases ASCII letters, turns `:` and `-` into `.`, collapses runs of `.` and trims `.` from both ends. `"Invoices:Read"` and `"invoices-read"` both become `"invoices.read"`. A `null` name becomes `""`.
  - `Capabilities.covers(capability, action)` says whether one capability covers an action, in any spelling of either. `*` covers every action. A name that ends in `.*` covers every action under that prefix at any depth, but not the prefix itself: `invoices.*` covers `invoices.read.draft`, not `invoices`.
  - `Capabilities.anyCovers(capabilities, action)` checks a collection and ignores `null` entries.
  - `Capabilities.WILDCARD` is the bare wildcard, `"*"`.
- `LumoAgent.hasCapability()` and `LumoAgent.requireCapability()` now use the new rules.
- `hasCapability()` reads only the agent's registered capabilities. The Ask API (`agent.ask()`) also applies your policies and the token's scope.

```java
Capabilities.normalize("Tool:Search-Web");          // "tool.search.web"
Capabilities.covers("users:*", "USERS-DELETE");     // true
Capabilities.covers("invoices.*", "invoices");      // false
```

### 3. `AgentBudget.exhausted()` Covers Every Limit (`io.lumoauth.model.AgentBudget`)

- Added the `reportedExhausted` record component (`Boolean`, JSON `exhausted`). The server sets it to `true` when any limit is reached: calls, tokens or cost, per hour, day or month. It is `null` when the server does not send it.
- `AgentBudget.exhausted()` now returns `reportedExhausted` when the server sent it. Otherwise it compares the daily token cap with today's usage, as in 1.3.0.
- `LumoAgent.checkBudget()` uses `exhausted()`, so it follows the same rules.
- The other budget fields, such as call and cost limits and their usage, are in `AgentBudget.raw()`.

---

## Upgrade Notes

- **Capability checks can now return `true` where 1.3.0 returned `false`.** An agent that holds `tool.search_web` now passes `hasCapability("tool:search_web")`, and an agent that holds `tool.*` now passes `hasCapability("tool.search_web")`. This change also applies to `requireCapability()`. The new answers match the server's. Review any code that relied on an exact string comparison.
- **`checkBudget()` can now throw `LumoAuthBudgetExceededException` before the daily token cap is reached.** Call limits, hourly limits and cost limits also count now.
- **`AgentBudget` has a fourth record component.** The three-argument constructor `AgentBudget(int, int, Map)` stays, so existing calls compile and link. A record pattern that deconstructs `AgentBudget` (Java 21 and later) must add the `Boolean reportedExhausted` component.
- **The Spring Boot starter has no code changes.** `LumoAuthTokenIntrospector` still adds one authority per capability, in the stored form. Spring Security `hasAuthority(...)` checks therefore compare exact names and do not expand wildcards.
- No dependency changes in this release. The SDK still targets Java 17.

---

## Documentation & Tests

- Updated the README's agent section: a `reportUsage()` example and the capability matching rules.
- Added a dated `1.4.0` section to `CHANGELOG.md`.
- Added `CapabilitiesTest`:
  - The shared contract cases in `sdk-contract/vectors/agent-capabilities.json`, which the contract repo also checks against the server's own matcher. Set `LUMO_SDK_CONTRACT` to point the tests at a contract checkout. Without one, the contract test is skipped.
  - Inline capability cases.
- Added three tests to `LumoAgentTest`: capability guards that match like the server, `reportUsage()` with the refreshed cached budget, and a budget guard that uses the server's verdict.

---

## Commit Log (`java-v1.3.0..java-v1.4.0`)

- `daadf64` — `release: lumo-auth-java@1.4.0`
- `e214e07` — `feat: add reportUsage method to LumoAgent for tracking model usage and costs`
- `b437597` — `feat: enhance budget handling to utilize server's verdict for exhaustion status`
- `917c786` — `feat: implement capability matching to align with server behavior`
- `a79ee67` — `release: add release notes for LumoAuth Java SDK v1.3.0`
