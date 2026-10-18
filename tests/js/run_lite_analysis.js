"use strict";

const fs = require("node:fs");
const vm = require("node:vm");

const html = fs.readFileSync(process.argv[2], "utf8");
const match = html.match(/<script>([\s\S]*?)<\/script>/);
if (!match) throw new Error("No se encontró el script de HeaderGuard Lite.");

const context = { console, TextEncoder };
context.globalThis = context;
vm.createContext(context);
vm.runInContext(match[1], context, { filename: "HeaderGuard-Lite.html" });

let payload = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { payload += chunk; });
process.stdin.on("end", () => {
  try {
    const request = JSON.parse(payload);
    const api = context.HeaderGuardLite;
    let result;
    if (request.operation === "quality") {
      result = api.quality(request.name, request.value);
    } else {
      result = api.analyzeHeaders(api.parseRawHeaders(request.raw));
    }
    process.stdout.write(JSON.stringify({ ok: true, result }));
  } catch (error) {
    process.stdout.write(JSON.stringify({ ok: false, error: error.message }));
  }
});
