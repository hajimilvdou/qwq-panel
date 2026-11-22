<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR-0028: External CLI Agent Sandbox, Process Isolation & Loopback MCP Bridge

- **Status**: Accepted (Implemented in `internal/agentsession/`)
- **Date**: 2026-11-21
- **Scope**: `claude-code`, `codex`, `opencode`, `dsh`, and generic `acp` CLI cores

## Context

`qwq` supports delegating VPS operational turns to external agent CLIs (`claude-code`, `codex`, `opencode`, and protocol-compatible ACP agents such as `dsh`) while preserving the host's single operation/approval/RBAC/audit boundary (ADR-0004, ADR-0010, ADR-0031). External CLIs are untrusted processes: they must never directly read host secrets (`master.key`, `qwq.db`, plugin `.token`, or operator OAuth/config directories) or bypass `operations.Run` and human approval cards.

## Decision

Every external CLI core launched by `internal/agentsession` enforces four mandatory security & resource boundaries:

1. **Zero Host Credential / Filesystem Inheritance (`OSProcessLauncher` + `SanitizedEnv`)**:
   - Child environments use a minimal allowlist (`PATH`, locale, `TERM`, `TZ`, `NO_COLOR`, proxy vars) and strictly exclude host `HOME`, `XDG_*`, `CODEX_HOME`, `OPENCODE_CONFIG_DIR`, `DSH_HOME`, `CLAUDE_CONFIG_DIR`, and any host secret variable (`QWQ_MASTER*`, `QWQ_SESSION_SECRET*`, `*PASSWORD*`, `*PRIVATE_KEY*`).
   - Each turn allocates an ephemeral `0700` isolated temp home (`qwq-cli-home-*`) with dedicated `workspace/`, `config/`, `data/`, `cache/`, and `tmp/` subdirectories, removed on `Close()`.
   - On Unix when the host runs as `root` (`euid == 0`) and no explicit `RunAsUID/RunAsGID` is set, `OSProcessLauncher` drops child credentials by default to `nobody` (`65534:65534`, empty supplementary groups) and transfers ownership of the ephemeral temp home to that UID/GID so `0600` root-owned host files remain unreadable even by exact absolute path.
   - Global `AIProvider` API keys are bridged only when explicitly authorized via session `provider_id` (`ResolveProviderEnv`) and scrubbed in memory when the turn ends.

2. **Process-Group Isolation & Bounded Descendant Reaping**:
   - Every Unix child starts in its own process group (`SysProcAttr{Setpgid: true}`) with explicit pipe FDs for `stderr`.
   - `Close(grace)` sends `SIGTERM` to the entire process group (`-pid`), waits up to `grace`, then sends `SIGKILL` to `-pid`, closes inherited pipe readers, and polls `kill(-pid, 0)` until `ESRCH` (bounded by `hardReapTimeout`) before removing the isolated temp home or releasing the concurrency slot. This covers SIGTERM-ignoring descendants and early parent exits cleanly.

3. **Authenticated Loopback MCP Tool Bridge (`LoopbackMCPServer`)**:
   - External CLIs are restricted from direct local shell/file mutation (e.g., Claude Code `--strict-mcp-config --disallowedTools Bash,Write,Edit,MultiEdit,NotebookEdit`; Codex `--sandbox read-only` + host approval router) and given an ephemeral `127.0.0.1:0` HTTP JSON-RPC MCP endpoint protected by a per-turn 256-bit CSPRNG Bearer token.
   - All tool calls route exclusively through `MCPBridge -> turn.Runner.RunTool -> operations.Run` under the session's AI actor (`session:<id>` on behalf of the owner) and authoritative `PermissionMode` (`read_only` / `safe` / `full`) + `PlanMode` ceiling.
   - The loopback HTTP server enforces strict timeouts, `256 KiB + 1` body overflow rejection (`413`), single-document strict JSON depth (`<= 32`) & duplicate-key rejection (`400`), bounded in-flight concurrency (`429`), and turn-linked context cancellation + forced socket close on `Close()`.

4. **1C1G Concurrency Ceiling & Persisted Context Compaction**:
   - `OSProcessLauncher` enforces a global 1-slot concurrency gate (`globalCLISem`) to protect 1C1G VPS hosts from concurrent Node/Rust CLI memory spikes.
   - Context compaction (`/compact` and `CompactSession`) persists a bounded `compaction_checkpoint` inside `agent_sessions.config_json` (without deleting immutable `agent_session_messages` or `audit_log` rows), taking real effect on subsequent turns and across host restarts.

## Consequences

- External CLIs behave uniformly in the Web Shell AI workspace while remaining strictly bounded by host RBAC, approvals, and filesystem permissions.
- Real external CLI binary E2E verification remains tracked separately from protocol/OS-process fixture verification until target CLI binaries are installed on the test VPS.
