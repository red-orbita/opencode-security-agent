import type { Plugin } from "@opencode-ai/plugin"
import path from "path"
import { existsSync } from "fs"

/**
 * OpenCode Security Agent -- Runtime Protection Plugin (v1.2.0)
 *
 * Intercepts every tool call via the `tool.execute.before` event and checks
 * it against a local IOC library using the bundled Python script. Blocks
 * credential exfiltration, known-malicious domains, reverse shells,
 * curl|bash pipes, and prompt injection attempts before they execute.
 *
 * Zero LLM cost -- pure local pattern matching (~30-80ms per call).
 * Fail-open -- if the check crashes or times out, the tool call proceeds.
 *
 * License: GPL-3.0
 */

const TIMEOUT_MS = 5000

const BLOCK_REASON_PATTERN =
  /\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]|blocked|Security Agent|prompt injection/i

/**
 * Self-protection: patterns that match allowlist and security config files.
 * These files must NEVER be writable by the agent — only by a human
 * editing them directly outside of OpenCode.
 */
const SELF_PROTECTED_PATTERNS = [
  /sentinel-allowlist\.json/i,
  /\.security\/.*\.json$/i,
  /mcp-sentinel-threats\.json/i,
  /iocs\.json$/i,
]

/**
 * Tools that can write files — we inspect their args for self-protection.
 */
const WRITE_TOOLS = new Set(["write", "edit", "bash"])

function isSelfProtectedPath(tool: string, args: Record<string, any>): string | null {
  // For write/edit tools, only check the target file path (not content)
  if (tool === "write" || tool === "edit") {
    const targets = [args.filePath, args.newFilePath].filter(Boolean)
    for (const val of targets) {
      if (typeof val !== "string") continue
      for (const pattern of SELF_PROTECTED_PATTERNS) {
        if (pattern.test(val)) return val
      }
    }
    return null
  }

  // For bash, only block commands that clearly write to protected files
  if (tool === "bash") {
    const cmd = args.command || ""
    if (typeof cmd !== "string") return null
    const writePatterns = [
      />\s*\S*sentinel-allowlist/i,
      /tee\s+\S*sentinel-allowlist/i,
      /cp\s+.*sentinel-allowlist/i,
      /mv\s+.*sentinel-allowlist/i,
      /rm\s+.*sentinel-allowlist/i,
      />\s*\S*iocs\.json/i,
      /tee\s+\S*iocs\.json/i,
      /rm\s+.*iocs\.json/i,
      />\s*\S*mcp-sentinel-threats/i,
      /rm\s+.*mcp-sentinel-threats/i,
    ]
    for (const wp of writePatterns) {
      if (wp.test(cmd)) return cmd
    }
  }

  return null
}

export const SecurityAgentPlugin: Plugin = async ({
  project,
  client,
  $,
  directory,
  worktree,
}) => {
  // Locate the Python hook script relative to this plugin file
  const pluginDir = import.meta.dir
  const hookScript = path.join(pluginDir, "sentinel_preflight.py")

  return {
    "tool.execute.before": async (input, output) => {
      const startTime = performance.now()
      try {
        // --- SELF-PROTECTION: block writes to allowlist/security files ---
        if (WRITE_TOOLS.has(input.tool)) {
          const protectedMatch = isSelfProtectedPath(input.tool, output.args)
          if (protectedMatch) {
            throw new Error(
              `OpenCode Security Agent blocked a ${input.tool} call.\n` +
              `Reason: [CRITICAL] self-protection: writing to security configuration files ` +
              `is not allowed from within the agent.\n` +
              `Matched: ${protectedMatch}\n\n` +
              `ACTION REQUIRED: If this operation needs an allowlist exception, ` +
              `tell the human:\n` +
              `  "Please add the following to .security/sentinel-allowlist.json ` +
              `and save the file outside of OpenCode, then retry."\n` +
              `The agent CANNOT modify this file — only a human can.`
            )
          }
        }
        // Verify the hook script exists before spawning
        if (!existsSync(hookScript)) {
          await client.app.log({
            body: {
              service: "security-agent",
              level: "warn",
              message: `Hook script not found at ${hookScript} (fail-open)`,
            },
          })
          return
        }

        // Build the payload matching the hook's expected format
        const payload = JSON.stringify({
          tool_name: input.tool,
          tool_input: output.args,
        })

        // Run the Python hook as a subprocess with safe stdin piping
        const proc = Bun.spawn(["python3", hookScript], {
          stdin: new Blob([payload]),
          stdout: "pipe",
          stderr: "pipe",
        })

        // Apply timeout
        const timeoutPromise = new Promise<"timeout">((resolve) =>
          setTimeout(() => resolve("timeout"), TIMEOUT_MS),
        )
        const exitPromise = proc.exited

        const race = await Promise.race([exitPromise, timeoutPromise])

        if (race === "timeout") {
          proc.kill()
          const elapsed = (performance.now() - startTime).toFixed(1)
          await client.app.log({
            body: {
              service: "security-agent",
              level: "warn",
              message: `Security check timed out after ${elapsed}ms (fail-open)`,
            },
          })
          return
        }

        const stdout = await new Response(proc.stdout).text()
        const elapsed = (performance.now() - startTime).toFixed(1)

        await client.app.log({
          body: {
            service: "security-agent",
            level: "debug",
            message: `Security check completed in ${elapsed}ms for tool=${input.tool}`,
          },
        })

        const response = JSON.parse(stdout.trim())

        if (response.decision === "block") {
          const reason =
            response.reason || "Blocked by OpenCode Security Agent"
          throw new Error(reason)
        }

        // For "allow" with warning, log it but don't block
        if (response.reason && response.decision === "allow") {
          await client.app.log({
            body: {
              service: "security-agent",
              level: "warn",
              message: response.reason,
            },
          })
        }
      } catch (error: any) {
        // If the error was thrown by us (block decision), re-throw
        if (BLOCK_REASON_PATTERN.test(error.message || "")) {
          throw error
        }

        // Otherwise fail-open: log and allow the tool call to proceed
        const elapsed = (performance.now() - startTime).toFixed(1)
        await client.app.log({
          body: {
            service: "security-agent",
            level: "warn",
            message: `Security check failed after ${elapsed}ms (fail-open): ${error.message}`,
          },
        })
      }
    },
  }
}
