#!/usr/bin/env node
/**
 * Build-stage: resolve package.json bin → /app/mcp-launch (no npx at runtime).
 * Usage: node resolve_npm_bin.js <package-identifier>
 * Prints REASON:no_bin | REASON:ambiguous_bin on failure (exit 1).
 */
"use strict";

const fs = require("fs");
const path = require("path");

const MCP_LAUNCH = "/app/mcp-launch";
const VERSIONS_PATH = "/app/aos-bp-installed-versions.json";
const SDK_NAME = "@modelcontextprotocol/sdk";
const ident = process.argv[2];
if (!ident) {
  console.error("REASON:no_bin");
  process.exit(1);
}

const bare = ident.includes("/") ? ident.split("/").pop() : ident;
const roots = ["/usr/local/lib/node_modules", "/usr/lib/node_modules"];
let pkgDir = null;
for (const root of roots) {
  const cand = path.join(root, ident);
  if (fs.existsSync(path.join(cand, "package.json"))) {
    pkgDir = cand;
    break;
  }
}
if (!pkgDir) {
  console.error("REASON:no_bin");
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));
const binField = pkg.bin;
let rel = null;
if (typeof binField === "string") {
  rel = binField;
} else if (binField && typeof binField === "object") {
  const keys = Object.keys(binField);
  if (keys.length === 0) {
    console.error("REASON:no_bin");
    process.exit(1);
  }
  if (Object.prototype.hasOwnProperty.call(binField, bare)) {
    rel = binField[bare];
  } else if (keys.length === 1) {
    rel = binField[keys[0]];
  } else {
    console.error("REASON:ambiguous_bin");
    process.exit(1);
  }
} else {
  console.error("REASON:no_bin");
  process.exit(1);
}

const abs = path.resolve(pkgDir, rel);
if (!fs.existsSync(abs)) {
  console.error("REASON:no_bin");
  process.exit(1);
}

const script = "#!/bin/sh\nexec node " + JSON.stringify(abs) + ' "$@"\n';
fs.writeFileSync(MCP_LAUNCH, script, { mode: 0o755 });

function readPkgVersion(name, baseDirs) {
  for (const base of baseDirs) {
    const cand = path.join(base, name, "package.json");
    try {
      if (fs.existsSync(cand)) {
        const meta = JSON.parse(fs.readFileSync(cand, "utf8"));
        if (meta && typeof meta.version === "string") {
          return meta.version;
        }
      }
    } catch (_err) {
      /* ignore — versions are best-effort */
    }
  }
  return null;
}

const versionBases = [path.join(pkgDir, "node_modules"), ...roots];
const versions = {};
if (typeof pkg.version === "string") {
  versions[ident] = pkg.version;
}
const sdkVer = readPkgVersion(SDK_NAME, versionBases);
if (sdkVer) {
  versions[SDK_NAME] = sdkVer;
}
try {
  fs.writeFileSync(VERSIONS_PATH, JSON.stringify(versions));
} catch (_err) {
  /* ignore */
}
