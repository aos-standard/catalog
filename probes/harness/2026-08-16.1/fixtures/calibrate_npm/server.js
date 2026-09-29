#!/usr/bin/env node
/**
 * No-op MCP stdio server for instrument calibration.
 * Responds to initialize / tools/list / tools/call; does not touch network or disk.
 */
"use strict";

const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, terminal: false });

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}

function replyError(id, code, message) {
  process.stdout.write(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n"
  );
}

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch {
    return;
  }
  const method = msg.method;
  const id = msg.id;
  if (method === "initialize") {
    reply(id, {
      protocolVersion: "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "aos-bp-calibrate-npm", version: "0.0.1" },
    });
    return;
  }
  if (method === "notifications/initialized" || method === "initialized") {
    return;
  }
  if (method === "tools/list") {
    reply(id, {
      tools: [
        {
          name: "noop",
          description: "calibration noop",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    });
    return;
  }
  if (method === "tools/call") {
    reply(id, { content: [{ type: "text", text: "ok" }] });
    return;
  }
  if (id != null) {
    replyError(id, -32601, "Method not found");
  }
});
