"use strict";

const fs = require("node:fs");
const vm = require("node:vm");

const request = JSON.parse(fs.readFileSync(0, "utf8"));
const html = fs.readFileSync(process.argv[2], "utf8");
const match = html.match(/<script>([\s\S]*?)<\/script>/);
if (!match) throw new Error("No se encontró el script de HeaderGuard Lite.");

const stored = new Map();
if (request.storageMode === "corrupt") stored.set("headerguard.lite.history.v1", "not-json");
const localStorage = {
  getItem(key) {
    if (request.storageMode === "throw") throw new Error("storage blocked");
    return stored.has(key) ? stored.get(key) : null;
  },
  setItem(key, value) {
    if (request.storageMode === "throw") throw new Error("storage blocked");
    stored.set(key, String(value));
  },
};
const context = { console, TextEncoder, localStorage };
context.globalThis = context;
vm.createContext(context);
vm.runInContext(match[1], context, { filename: "HeaderGuard-Lite.html" });

try {
  const api = context.HeaderGuardLite;
  let result;
  if (request.operation === "quality") {
    result = api.quality(request.name, request.value);
  } else if (request.operation === "configuration") {
    result = api.configurationFor(request.server);
  } else if (request.operation === "reportHTML") {
    result = api.reportHTML(request.report);
  } else if (request.operation === "export") {
    result = api.exportableReport(request.report);
  } else if (request.operation === "history") {
    for (const analysis of request.analyses || []) api.saveHistory(analysis);
    result = api.getHistory();
  } else {
    result = api.analyzeHeaders(api.parseRawHeaders(request.raw));
  }
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: error.message }));
}
