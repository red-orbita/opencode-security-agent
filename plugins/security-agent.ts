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
