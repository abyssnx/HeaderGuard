(() => {
  "use strict";

  const RULES = __HEADERGUARD_RULES__;
  const COOKIE_REFERENCE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie";
  const OWASP_REFERENCE = "https://owasp.org/www-project-secure-headers/";
  const THEME_KEY = "headerguard.lite.theme.v1";
  const HISTORY_KEY = "headerguard.lite.history.v1";
  const SECURITY_PROFILE = [
    ["Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"],
    ["Strict-Transport-Security", "max-age=31536000; includeSubDomains"],
    ["X-Content-Type-Options", "nosniff"],
    ["X-Frame-Options", "DENY"],
    ["Referrer-Policy", "strict-origin-when-cross-origin"],
    ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
    ["Cross-Origin-Opener-Policy", "same-origin"],
    ["Cross-Origin-Resource-Policy", "same-origin"],
    ["Cross-Origin-Embedder-Policy", "require-corp"],
  ];
  let currentReport = null;
  let toastTimer = null;
  const SAFE_REFERRER_POLICIES = new Set([
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
  ]);

  function quality(name, value) {
    const lowered = value.toLowerCase();
    if (name === "strict-transport-security") {
      const match = lowered.match(/(?:^|;)\s*max-age\s*=\s*(\d+)/);
      if (!match) return { status: "warning", issue: "Incluye una directiva max-age válida." };
      if (Number(match[1]) < 31536000) {
        return { status: "warning", issue: "El max-age es inferior al año recomendado." };
      }
    } else if (name === "content-security-policy") {
      const risky = ["'unsafe-inline'", "'unsafe-eval'"].filter((token) => lowered.includes(token));
      if (/(?:^|[;\s])\*(?:[;\s]|$)/.test(lowered)) risky.push("*");
      if (risky.length) {
        return { status: "warning", issue: `Revisa fuentes permisivas: ${risky.join(", ")}.` };
      }
      if (!lowered.includes("default-src") && !lowered.includes("script-src")) {
        return { status: "warning", issue: "Define al menos default-src o script-src." };
      }
    } else if (name === "x-content-type-options" && lowered !== "nosniff") {
      return { status: "warning", issue: "El único valor recomendado es nosniff." };
    } else if (name === "x-frame-options" && !["deny", "sameorigin"].includes(lowered)) {
      return { status: "warning", issue: "Usa DENY o SAMEORIGIN." };
    } else if (name === "referrer-policy") {
      const policies = lowered.split(",").map((item) => item.trim());
      if (!policies.some((item) => SAFE_REFERRER_POLICIES.has(item))) {
        return {
          status: "warning",
          issue: "Usa una política restrictiva como strict-origin-when-cross-origin.",
        };
      }
    } else if (name === "permissions-policy" && lowered.includes("*")) {
      return {
        status: "warning",
        issue: "Evita permitir capacidades sensibles a todos los orígenes (*).",
      };
    } else if (
      name === "cross-origin-opener-policy"
      && !["same-origin", "same-origin-allow-popups"].includes(lowered)
    ) {
      return { status: "warning", issue: "Valora same-origin para un aislamiento fuerte." };
    } else if (
      name === "cross-origin-resource-policy"
      && !["same-origin", "same-site"].includes(lowered)
    ) {
      return {
        status: "warning",
        issue: "Usa same-origin o same-site cuando sea compatible.",
      };
    } else if (
      name === "cross-origin-embedder-policy"
      && !["require-corp", "credentialless"].includes(lowered)
    ) {
      return {
        status: "warning",
        issue: "Usa require-corp o credentialless cuando sea compatible.",
      };
    }
    return { status: "secure", issue: null };
  }

  function normalizeHeaders(headers) {
    const normalized = Object.create(null);
    for (const [rawName, rawValue] of Object.entries(headers)) {
      const name = rawName.trim().toLowerCase();
      const value = rawValue.trim();
      if (name && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(name + value)) {
        normalized[name] = value;
      }
    }
    return normalized;
  }

  function analyzeCookies(headers) {
    const rawCookies = [];
    for (const [rawName, rawValue] of Object.entries(headers)) {
      if (rawName.trim().toLowerCase() === "set-cookie") {
        rawCookies.push(...rawValue.split("\n").map((line) => line.trim()).filter(Boolean));
      }
    }

    const cookies = [];
    for (const rawCookie of rawCookies) {
      const parts = rawCookie.split(";").map((part) => part.trim()).filter(Boolean);
      if (!parts.length || !parts[0].includes("=")) continue;
      const name = parts[0].split("=", 1)[0].trim().slice(0, 128) || "(sin nombre)";
      const attributes = Object.create(null);
      for (const part of parts.slice(1)) {
        const separator = part.indexOf("=");
        const key = (separator === -1 ? part : part.slice(0, separator)).trim().toLowerCase();
        attributes[key] = separator === -1 ? null : part.slice(separator + 1).trim().toLowerCase();
      }
      const secure = Object.hasOwn(attributes, "secure");
      const httpOnly = Object.hasOwn(attributes, "httponly");
      const sameSite = attributes.samesite ?? null;
      const issues = [];
      if (!secure) issues.push("Falta Secure");
      if (!httpOnly) issues.push("Falta HttpOnly; confirma si JavaScript necesita acceder a ella");
      if (!["lax", "strict", "none"].includes(sameSite)) {
        issues.push("Falta un atributo SameSite explícito");
      }
      if (sameSite === "none" && !secure) issues.push("SameSite=None requiere Secure");
      const lowerName = name.toLowerCase();
      if (lowerName.startsWith("__secure-") && !secure) {
        issues.push("El prefijo __Secure- requiere Secure");
      }
      if (
        lowerName.startsWith("__host-")
        && (!secure || attributes.path !== "/" || Object.hasOwn(attributes, "domain"))
      ) {
        issues.push("El prefijo __Host- requiere Secure, Path=/ y ningún Domain");
      }
      cookies.push({
        name,
        status: issues.length ? "warning" : "secure",
        secure,
        http_only: httpOnly,
        same_site: sameSite,
        issues,
      });
    }
    return {
      count: cookies.length,
      secure: cookies.filter((cookie) => cookie.status === "secure").length,
      warnings: cookies.filter((cookie) => cookie.status === "warning").length,
      reference: COOKIE_REFERENCE,
      cookies,
    };
  }

  function analyzeHeaders(headers) {
    const normalized = normalizeHeaders(headers);
    const results = [];
    let score = 0;
    for (const rule of RULES) {
      const value = normalized[rule.name];
      const present = Boolean(value);
      const signal = present ? quality(rule.name, value) : { status: "missing", issue: null };
      const earned = signal.status === "secure"
        ? rule.weight
        : present
          ? Math.max(0, rule.weight - 5)
          : 0;
      score += earned;
      results.push({
        name: rule.name,
        present,
        value: value ?? null,
        purpose: rule.purpose,
        recommendation: rule.recommendation,
        weight: rule.weight,
        earned,
        status: signal.status,
        issue: signal.issue,
        reference: rule.reference,
      });
    }
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F";
    const priorities = results
      .filter((item) => item.status !== "secure")
      .slice(0, 3)
      .map((item) => ({
        name: item.name,
        status: item.status,
        message: item.issue || item.recommendation,
      }));
    return {
      score,
      grade,
      present: results.filter((item) => item.present).length,
      secure: results.filter((item) => item.status === "secure").length,
      warnings: results.filter((item) => item.status === "warning").length,
      missing: results.filter((item) => item.status === "missing").length,
      total: results.length,
      priorities,
      results,
      cookies: analyzeCookies(headers),
    };
  }

  function parseRawHeaders(raw) {
    if (new TextEncoder().encode(raw).length > 32768) {
      throw new Error("El bloque de cabeceras supera el límite de 32 KB.");
    }
    const headers = Object.create(null);
    const lines = raw.replaceAll("\r\n", "\n").split("\n");
    if (lines.length && lines[0].toUpperCase().startsWith("HTTP/")) lines.shift();
    for (const line of lines) {
      if (!line.trim()) continue;
      if (/^\s/.test(line)) {
        throw new Error("No se admiten cabeceras continuadas en varias líneas.");
      }
      const separator = line.indexOf(":");
      if (separator === -1) {
        throw new Error(`Línea de cabecera no válida: ${line.slice(0, 80)}`);
      }
      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (!name || /\s/.test(name)) throw new Error("Nombre de cabecera no válido.");
      if (name.toLowerCase() === "set-cookie") {
        const existing = Object.keys(headers).find((key) => key.toLowerCase() === "set-cookie");
        if (existing) headers[existing] = `${headers[existing]}\n${value}`;
        else headers[name] = value;
      } else {
        headers[name] = value;
      }
    }
    if (!Object.keys(headers).length) {
      throw new Error("Pega al menos una cabecera con el formato Nombre: valor.");
    }
    return headers;
  }

  function safeStorage(action, fallback = null) {
    try {
      return action();
    } catch {
      return fallback;
    }
  }

  function getHistory() {
    return safeStorage(() => {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      if (!Array.isArray(parsed)) return [];
      const validGrades = new Set(["A", "B", "C", "D", "F"]);
      return parsed
        .filter((item) => (
          item
          && typeof item === "object"
          && typeof item.date === "string"
          && Number.isFinite(Date.parse(item.date))
          && Number.isInteger(item.score)
          && item.score >= 0
          && item.score <= 100
          && validGrades.has(item.grade)
          && [item.secure, item.warnings, item.missing].every(
            (value) => Number.isInteger(value) && value >= 0 && value <= RULES.length,
          )
        ))
        .slice(0, 6)
        .map((item) => ({
          date: item.date,
          score: item.score,
          grade: item.grade,
          secure: item.secure,
          warnings: item.warnings,
          missing: item.missing,
        }));
    }, []);
  }

  function saveHistory(analysis) {
    const entry = {
      date: new Date().toISOString(),
      score: analysis.score,
      grade: analysis.grade,
      secure: analysis.secure,
      warnings: analysis.warnings,
      missing: analysis.missing,
    };
    const history = [entry, ...getHistory()].slice(0, 6);
    safeStorage(() => localStorage.setItem(HISTORY_KEY, JSON.stringify(history)));
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;",
    })[character]);
  }

  function configurationFor(server) {
    if (server === "nginx") {
      return SECURITY_PROFILE.map(([name, value]) => `add_header ${name} "${value}" always;`).join("\n");
    }
    if (server === "apache") {
      return [
        "<IfModule mod_headers.c>",
        ...SECURITY_PROFILE.map(([name, value]) => `  Header always set ${name} "${value}"`),
        "</IfModule>",
      ].join("\n");
    }
    if (server === "fastapi") {
      const entries = SECURITY_PROFILE.map(
        ([name, value]) => `    ${JSON.stringify(name)}: ${JSON.stringify(value)},`,
      ).join("\n");
      return `SECURITY_HEADERS = {\n${entries}\n}\n\n@app.middleware("http")\nasync def security_headers(request, call_next):\n    response = await call_next(request)\n    for name, value in SECURITY_HEADERS.items():\n        response.headers.setdefault(name, value)\n    return response`;
    }
    const calls = SECURITY_PROFILE.map(
      ([name, value]) => `  res.setHeader(${JSON.stringify(name)}, ${JSON.stringify(value)});`,
    ).join("\n");
    return `app.use((req, res, next) => {\n${calls}\n  next();\n});`;
  }

  function exportableReport(report = currentReport) {
    if (!report) return null;
    return {
      generator: "HeaderGuard Lite by abyssnx",
      generated_at: new Date().toISOString(),
      source: "Cabeceras pegadas · análisis local",
      analysis: report.analysis,
    };
  }

  function reportHTML(report) {
    const rows = report.analysis.results.map((item) => `
      <tr><td>${escapeHTML(item.name)}</td><td><span class="state ${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td><td>${escapeHTML(item.value || "No detectada")}</td><td>${escapeHTML(item.issue || item.recommendation)}</td></tr>`).join("");
    const cookies = report.analysis.cookies.cookies.length
      ? `<h2>Cookies</h2><p>Los valores se eliminaron antes de crear el informe.</p><table><thead><tr><th>Nombre</th><th>Estado</th><th>Atributos</th></tr></thead><tbody>${report.analysis.cookies.cookies.map((cookie) => `<tr><td>${escapeHTML(cookie.name)}</td><td>${escapeHTML(cookie.status)}</td><td>Secure: ${cookie.secure ? "sí" : "no"} · HttpOnly: ${cookie.http_only ? "sí" : "no"} · SameSite: ${escapeHTML(cookie.same_site || "no definido")}</td></tr>`).join("")}</tbody></table>`
      : "";
    return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Informe HeaderGuard Lite</title><style>body{font:15px/1.55 system-ui;background:#07101f;color:#eef7ff;margin:0;padding:40px}main{max-width:1050px;margin:auto}.brand{color:#40e7d0;letter-spacing:.12em;text-transform:uppercase}.score{font-size:54px;margin:8px 0;color:#60e6ad}table{width:100%;border-collapse:collapse;margin:24px 0 40px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #263653}th{color:#91a4bf}.state{padding:3px 8px;border-radius:99px;background:#1c2b43}.warning,.missing{color:#ffc56b}.secure{color:#60e6ad}footer{margin-top:50px;color:#91a4bf}@media print{body{background:#fff;color:#172033}.brand,.score{color:#087d91}}</style></head><body><main><p class="brand">HeaderGuard Lite · abyssnx</p><h1>Informe de seguridad HTTP</h1><p>${escapeHTML(report.source)} · ${escapeHTML(report.generated_at)}</p><div class="score">${report.analysis.score}/100 · ${escapeHTML(report.analysis.grade)}</div><p>${report.analysis.secure} correctas · ${report.analysis.warnings} mejorables · ${report.analysis.missing} ausentes</p><h2>Cabeceras evaluadas</h2><table><thead><tr><th>Cabecera</th><th>Estado</th><th>Valor</th><th>Recomendación</th></tr></thead><tbody>${rows}</tbody></table>${cookies}<footer>Generado localmente con HeaderGuard Lite by abyssnx · Este informe no sustituye una auditoría profesional.</footer></main></body></html>`;
  }

  function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function makeReference(label, href) {
    const link = makeElement("a", "reference-link", `${label} ↗`);
    link.href = href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    return link;
  }

  function showToast(message) {
    const toast = document.querySelector("#toast");
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.add("visible");
    toastTimer = setTimeout(() => toast.classList.remove("visible"), 2400);
  }

  function renderHistory() {
    const list = document.querySelector("#history-list");
    const history = getHistory();
    list.replaceChildren();
    if (!history.length) {
      list.append(makeElement("p", "empty-history", "Todavía no hay análisis guardados."));
      return;
    }
    const formatter = new Intl.DateTimeFormat("es-ES", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
    for (const item of history) {
      const row = makeElement("article", "history-item");
      const copy = makeElement("div");
      copy.append(
        makeElement("strong", "", `Nota ${item.grade}`),
        makeElement("span", "", formatter.format(new Date(item.date))),
      );
      row.append(copy, makeElement("div", "history-score", String(item.score)));
      list.append(row);
    }
  }

  function updateConfiguration() {
    const output = document.querySelector("#config-output");
    output.textContent = configurationFor(document.querySelector("#server-type").value);
  }

  function downloadBlob(content, type, filename) {
    const blob = new Blob([content], { type });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function copyText(value, successMessage) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(successMessage);
    } catch {
      showToast("No se pudo copiar automáticamente. Selecciona el texto manualmente.");
    }
  }

  function renderCookies(cookieAnalysis) {
    const panel = document.querySelector("#cookie-results");
    const list = document.querySelector("#cookie-list");
    list.replaceChildren();
    if (!cookieAnalysis.count) {
      panel.classList.add("hidden");
      return;
    }
    panel.classList.remove("hidden");
    document.querySelector("#cookie-summary").textContent = `${cookieAnalysis.secure} seguras · ${cookieAnalysis.warnings} a revisar · valores ocultos`;
    for (const cookie of cookieAnalysis.cookies) {
      const row = makeElement("article", `cookie-item ${cookie.status}`);
      const head = makeElement("div", "cookie-head");
      head.append(
        makeElement("strong", "", cookie.name),
        makeElement(
          "span",
          `cookie-status ${cookie.status}`,
          cookie.status === "secure" ? "Correcta" : "Revisar",
        ),
      );
      const attributes = makeElement("div", "cookie-attributes");
      attributes.append(
        makeElement("span", cookie.secure ? "active" : "", "Secure"),
        makeElement("span", cookie.http_only ? "active" : "", "HttpOnly"),
        makeElement("span", cookie.same_site ? "active" : "", `SameSite=${cookie.same_site || "—"}`),
      );
      row.append(head, attributes);
      if (cookie.issues.length) row.append(makeElement("p", "cookie-issues", cookie.issues.join(" · ")));
      list.append(row);
    }
    const guide = makeReference("Guía oficial de cookies", cookieAnalysis.reference);
    guide.classList.add("cookie-reference");
    list.append(guide);
  }

  function renderResults(report) {
    currentReport = report;
    const analysis = report.analysis;
    document.querySelector("#score").textContent = analysis.score;
    document.querySelector("#grade").textContent = analysis.grade;
    document.querySelector("#summary").textContent = `${analysis.present} de ${analysis.total} presentes`;
    document.querySelector("#secure-count").textContent = analysis.secure;
    document.querySelector("#warning-count").textContent = analysis.warnings;
    document.querySelector("#missing-count").textContent = analysis.missing;
    document.querySelector("#score-ring").style.setProperty("--score-angle", `${analysis.score * 3.6}deg`);

    const priorities = document.querySelector("#priority-list");
    priorities.replaceChildren();
    if (!analysis.priorities.length) {
      priorities.append(makeElement("p", "priority-empty", "✓ No hay acciones urgentes en estas nueve comprobaciones."));
    } else {
      for (const priority of analysis.priorities) {
        const card = makeElement("article", "priority-item");
        card.append(
          makeElement("strong", "", priority.name),
          makeElement("p", "", priority.message),
        );
        priorities.append(card);
      }
    }

    const icons = { secure: "✓", warning: "!", missing: "×" };
    const headers = document.querySelector("#header-list");
    headers.replaceChildren();
    for (const item of analysis.results) {
      const row = makeElement("article", `header-item ${item.status}`);
      row.append(makeElement("span", "state-icon", icons[item.status]));
      const identity = makeElement("div", "header-identity");
      identity.append(
        makeElement("div", "header-name", item.name),
        makeElement("div", "header-value", item.present ? item.value : "No detectada"),
      );
      const detail = makeElement("div", "header-detail");
      detail.append(makeElement("p", "", item.purpose));
      const guidance = item.status === "secure"
        ? `Configuración sólida · ${item.earned}/${item.weight} puntos.`
        : item.status === "warning"
          ? `${item.issue} · ${item.earned}/${item.weight} puntos.`
          : `Recomendación: ${item.recommendation}`;
      detail.append(makeElement("small", "", guidance));
      const references = makeElement("div", "reference-links");
      references.append(
        makeReference("MDN", item.reference),
        makeReference("OWASP", OWASP_REFERENCE),
      );
      detail.append(references);
      row.append(identity, detail);
      headers.append(row);
    }
    renderCookies(analysis.cookies);
    updateConfiguration();
    saveHistory(analysis);
    renderHistory();
    const results = document.querySelector("#results");
    results.classList.remove("hidden");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    document.querySelector(".theme-icon").textContent = selected === "dark" ? "☼" : "☾";
    document.querySelector("#theme-toggle").setAttribute(
      "aria-label",
      selected === "dark" ? "Activar tema claro" : "Activar tema oscuro",
    );
    safeStorage(() => localStorage.setItem(THEME_KEY, selected));
  }

  function initializeInterface() {
    const storedTheme = safeStorage(() => localStorage.getItem(THEME_KEY));
    const preferredTheme = globalThis.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
    applyTheme(storedTheme || preferredTheme);

    document.querySelector("#theme-toggle").addEventListener("click", () => {
      applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
    document.querySelector("#sample-button").addEventListener("click", () => {
      document.querySelector("#headers").value = [
        "HTTP/2 200",
        "content-security-policy: default-src 'self'; object-src 'none'",
        "strict-transport-security: max-age=31536000; includeSubDomains",
        "x-content-type-options: nosniff",
        "x-frame-options: DENY",
        "referrer-policy: strict-origin-when-cross-origin",
        "set-cookie: __Host-session=demo-value; Secure; HttpOnly; SameSite=Lax; Path=/",
      ].join("\n");
      const status = document.querySelector("#status");
      status.className = "status success";
      status.textContent = "Ejemplo cargado. Pulsa Analizar ahora.";
    });
    document.querySelector("#analyze-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const status = document.querySelector("#status");
      try {
        const headers = parseRawHeaders(document.querySelector("#headers").value);
        renderResults({ source: "pasted", analysis: analyzeHeaders(headers) });
        status.className = "status success";
        status.textContent = "Análisis completado en este dispositivo.";
      } catch (error) {
        status.className = "status";
        status.textContent = error.message;
      }
    });
    document.querySelector("#server-type").addEventListener("change", updateConfiguration);
    document.querySelector("#copy-config").addEventListener("click", () => {
      copyText(document.querySelector("#config-output").textContent, "Configuración copiada");
    });
    document.querySelector("#download-json").addEventListener("click", () => {
      const report = exportableReport();
      if (!report) return;
      downloadBlob(
        JSON.stringify(report, null, 2),
        "application/json;charset=utf-8",
        `headerguard-lite-${report.analysis.score}.json`,
      );
      showToast("Informe JSON descargado");
    });
    document.querySelector("#download-html").addEventListener("click", () => {
      const report = exportableReport();
      if (!report) return;
      downloadBlob(
        reportHTML(report),
        "text/html;charset=utf-8",
        `headerguard-lite-${report.analysis.score}.html`,
      );
      showToast("Informe HTML descargado");
    });
    document.querySelector("#copy-summary").addEventListener("click", () => {
      if (!currentReport) return;
      const analysis = currentReport.analysis;
      copyText(
        `HeaderGuard Lite: ${analysis.score}/100 (${analysis.grade}) · ${analysis.secure} correctas · ${analysis.warnings} mejorables · ${analysis.missing} ausentes.`,
        "Resumen copiado",
      );
    });
    document.querySelector("#copy-badge").addEventListener("click", () => {
      if (!currentReport) return;
      const analysis = currentReport.analysis;
      const color = analysis.score >= 90 ? "2ea44f" : analysis.score >= 55 ? "e3a008" : "d73a49";
      copyText(
        `![HeaderGuard](https://img.shields.io/badge/HeaderGuard-${analysis.score}%2F100-${color})`,
        "Badge copiado",
      );
    });
    document.querySelector("#print-report").addEventListener("click", () => globalThis.print());
    renderHistory();
    updateConfiguration();
  }

  if (typeof document !== "undefined") initializeInterface();

  globalThis.HeaderGuardLite = Object.freeze({
    rules: RULES,
    parseRawHeaders,
    quality,
    analyzeCookies,
    analyzeHeaders,
    renderResults,
    renderCookies,
    applyTheme,
    configurationFor,
    exportableReport,
    reportHTML,
    getHistory,
    saveHistory,
  });
})();
