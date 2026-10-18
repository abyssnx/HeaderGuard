const remoteTab = document.querySelector("#remote-tab");
const pasteTab = document.querySelector("#paste-tab");
const remotePanel = document.querySelector("#remote-panel");
const pastePanel = document.querySelector("#paste-panel");
const statusBox = document.querySelector("#status");
const resultsSection = document.querySelector("#results");
const toast = document.querySelector("#toast");
const HISTORY_KEY = "headerguard.history.v1";
const THEME_KEY = "headerguard.theme.v1";
let currentReport = null;
let toastTimer = null;
const OWASP_REFERENCE = "https://owasp.org/projects/secure-headers-project";
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

function safeStorage(action, fallback = null) {
  try {
    return action();
  } catch {
    return fallback;
  }
}

function switchTab(mode) {
  const remote = mode === "remote";
  remoteTab.classList.toggle("active", remote);
  pasteTab.classList.toggle("active", !remote);
  remoteTab.setAttribute("aria-selected", String(remote));
  pasteTab.setAttribute("aria-selected", String(!remote));
  remotePanel.classList.toggle("hidden", !remote);
  pastePanel.classList.toggle("hidden", remote);
  statusBox.textContent = "";
}

remoteTab.addEventListener("click", () => switchTab("remote"));
pasteTab.addEventListener("click", () => switchTab("paste"));

function setLoading(form, loading) {
  const button = form.querySelector("button[type='submit']");
  button.disabled = loading;
  button.querySelector("span").textContent = loading ? "Analizando…" : "Analizar";
  statusBox.className = loading ? "status loading" : "status";
  if (loading) statusBox.textContent = "Evaluando la configuración de seguridad…";
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function makeReference(label, url) {
  const link = makeElement("a", "reference-link", `${label} ↗`);
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
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

function showToast(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.add("visible");
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2600);
}

function getHistory() {
  return safeStorage(() => {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  }, []);
}

function sourceLabel(data) {
  if (!data.final_url) return "Cabeceras pegadas";
  try {
    return new URL(data.final_url).origin;
  } catch {
    return "URL pública";
  }
}

function saveHistory(data) {
  const analysis = data.analysis;
  const entry = {
    id: Date.now(),
    date: new Date().toISOString(),
    source: sourceLabel(data),
    score: analysis.score,
    grade: analysis.grade,
    secure: analysis.secure,
    warnings: analysis.warnings,
    missing: analysis.missing,
  };
  const history = [entry, ...getHistory()].slice(0, 6);
  safeStorage(() => localStorage.setItem(HISTORY_KEY, JSON.stringify(history)));
}

function renderHistory() {
  const history = getHistory();
  const list = document.querySelector("#history-list");
  list.replaceChildren();
  if (!history.length) {
    list.append(makeElement("p", "empty-history", "Todavía no hay análisis guardados."));
    return;
  }

  const dateFormatter = new Intl.DateTimeFormat("es-ES", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
  for (const item of history) {
    const row = makeElement("article", "history-item");
    const identity = makeElement("div", "history-identity");
    identity.append(makeElement("strong", "", item.source));
    identity.append(makeElement("span", "", dateFormatter.format(new Date(item.date))));
    const stats = makeElement("div", "history-stats");
    stats.append(makeElement("span", "", `${item.secure} correctas`));
    stats.append(makeElement("span", "", `${item.missing} ausentes`));
    const score = makeElement("div", `history-score grade-${item.grade}`, String(item.score));
    score.setAttribute("aria-label", `Puntuación ${item.score} sobre 100, nota ${item.grade}`);
    score.append(makeElement("small", "", item.grade));
    row.append(identity, stats, score);
    list.append(row);
  }
}

function renderComparison(previous, score) {
  const element = document.querySelector("#comparison");
  if (!previous) {
    element.classList.add("hidden");
    return;
  }
  const delta = score - previous.score;
  element.textContent = delta === 0 ? "= sin cambios" : `${delta > 0 ? "↑" : "↓"} ${Math.abs(delta)} puntos`;
  element.className = `pill comparison ${delta > 0 ? "up" : delta < 0 ? "down" : "same"}`;
}

function renderCookies(cookieAnalysis) {
  const panel = document.querySelector("#cookie-results");
  const list = document.querySelector("#cookie-list");
  list.replaceChildren();
  if (!cookieAnalysis?.count) {
    panel.classList.add("hidden");
    return;
  }

  panel.classList.remove("hidden");
  document.querySelector("#cookie-summary").textContent = `${cookieAnalysis.secure} seguras · ${cookieAnalysis.warnings} a revisar`;
  for (const cookie of cookieAnalysis.cookies) {
    const row = makeElement("article", `cookie-item ${cookie.status}`);
    const head = makeElement("div", "cookie-head");
    head.append(makeElement("strong", "", cookie.name));
    head.append(makeElement("span", `cookie-status ${cookie.status}`, cookie.status === "secure" ? "Correcta" : "Revisar"));
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

function configurationFor(server) {
  if (server === "nginx") {
    return SECURITY_PROFILE.map(([name, value]) => `add_header ${name} "${value}" always;`).join("\n");
  }
  if (server === "apache") {
    return ["<IfModule mod_headers.c>", ...SECURITY_PROFILE.map(([name, value]) => `  Header always set ${name} "${value}"`), "</IfModule>"].join("\n");
  }
  if (server === "fastapi") {
    const entries = SECURITY_PROFILE.map(([name, value]) => `    ${JSON.stringify(name)}: ${JSON.stringify(value)},`).join("\n");
    return `SECURITY_HEADERS = {\n${entries}\n}\n\n@app.middleware("http")\nasync def security_headers(request, call_next):\n    response = await call_next(request)\n    for name, value in SECURITY_HEADERS.items():\n        response.headers.setdefault(name, value)\n    return response`;
  }
  const calls = SECURITY_PROFILE.map(([name, value]) => `  res.setHeader(${JSON.stringify(name)}, ${JSON.stringify(value)});`).join("\n");
  return `app.use((req, res, next) => {\n${calls}\n  next();\n});`;
}

function updateConfiguration() {
  const server = document.querySelector("#server-type").value;
  document.querySelector("#config-output").textContent = configurationFor(server);
}

function renderResults(data) {
  currentReport = data;
  const analysis = data.analysis;
  const previous = getHistory()[0];
  document.querySelector("#score").textContent = analysis.score;
  document.querySelector("#grade").textContent = analysis.grade;
  const scoreRing = document.querySelector("#score-ring");
  scoreRing.className = `score-ring score-${analysis.score}`;
  scoreRing.dataset.grade = analysis.grade;
  document.querySelector("#summary").textContent = `${analysis.present} de ${analysis.total} presentes`;
  document.querySelector("#secure-count").textContent = analysis.secure;
  document.querySelector("#warning-count").textContent = analysis.warnings;
  document.querySelector("#missing-count").textContent = analysis.missing;
  document.querySelector("#top-priority").textContent = analysis.priorities[0]?.name || "Sin acciones urgentes";
  document.querySelector("#result-meta").textContent = data.final_url
    ? `${data.final_url} · HTTP ${data.status_code}${data.redirects.length ? ` · ${data.redirects.length} redirección(es)` : ""}`
    : "Cabeceras proporcionadas manualmente";
  renderComparison(previous, analysis.score);

  const icons = { secure: "✓", warning: "!", missing: "×" };
  const list = document.querySelector("#header-list");
  list.replaceChildren();
  for (const item of analysis.results) {
    const row = makeElement("article", `header-item ${item.status}`);
    row.append(makeElement("span", "state-icon", icons[item.status]));

    const identity = makeElement("div");
    identity.append(makeElement("div", "header-name", item.name));
    identity.append(makeElement("div", "header-value", item.present ? item.value : "No detectada"));
    row.append(identity);

    const detail = makeElement("div", "header-detail");
    detail.append(makeElement("p", "", item.purpose));
    const guidance = item.status === "secure"
      ? `Configuración sólida · ${item.earned}/${item.weight} puntos.`
      : item.status === "warning"
        ? `${item.issue} · ${item.earned}/${item.weight} puntos.`
        : `Recomendación: ${item.recommendation}`;
    detail.append(makeElement("small", "", guidance));
    const references = makeElement("div", "reference-links");
    references.append(makeReference("MDN", item.reference), makeReference("OWASP", OWASP_REFERENCE));
    detail.append(references);
    row.append(detail);
    list.append(row);
  }
  renderCookies(analysis.cookies);
  updateConfiguration();
  resultsSection.classList.remove("hidden");
  saveHistory(data);
  renderHistory();
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function submit(form, endpoint, payload) {
  setLoading(form, true);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "No se pudo completar el análisis.");
    renderResults(data);
    statusBox.textContent = "";
  } catch (error) {
    statusBox.textContent = error.message;
  } finally {
    setLoading(form, false);
  }
}

function exportableReport() {
  if (!currentReport) return null;
  return {
    generator: "HeaderGuard by abyssnx",
    generated_at: new Date().toISOString(),
    source: sourceLabel(currentReport),
    final_url: currentReport.final_url || null,
    status_code: currentReport.status_code || null,
    redirects: currentReport.redirects || [],
    analysis: currentReport.analysis,
  };
}

remotePanel.addEventListener("submit", (event) => {
  event.preventDefault();
  submit(remotePanel, "/api/scan", { url: document.querySelector("#url").value.trim() });
});

pastePanel.addEventListener("submit", (event) => {
  event.preventDefault();
  submit(pastePanel, "/api/analyze", { headers: document.querySelector("#headers").value });
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
  showToast("Ejemplo seguro cargado");
});

document.querySelector("#download-json").addEventListener("click", () => {
  const report = exportableReport();
  if (!report) return;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `headerguard-${report.analysis.score}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("Informe JSON descargado");
});

function reportHTML(report) {
  const rows = report.analysis.results.map((item) => `
    <tr><td>${escapeHTML(item.name)}</td><td><span class="state ${escapeHTML(item.status)}">${escapeHTML(item.status)}</span></td><td>${escapeHTML(item.value || "No detectada")}</td><td>${escapeHTML(item.issue || item.recommendation)}</td></tr>`).join("");
  const cookies = report.analysis.cookies?.cookies?.length
    ? `<h2>Cookies</h2><p>Los valores se han eliminado por privacidad.</p><table><thead><tr><th>Nombre</th><th>Estado</th><th>Atributos</th></tr></thead><tbody>${report.analysis.cookies.cookies.map((cookie) => `<tr><td>${escapeHTML(cookie.name)}</td><td>${escapeHTML(cookie.status)}</td><td>Secure: ${cookie.secure ? "sí" : "no"} · HttpOnly: ${cookie.http_only ? "sí" : "no"} · SameSite: ${escapeHTML(cookie.same_site || "no definido")}</td></tr>`).join("")}</tbody></table>`
    : "";
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Informe HeaderGuard</title><style>body{font:15px/1.55 system-ui;background:#070a17;color:#e9f2ff;margin:0;padding:40px}main{max-width:1050px;margin:auto}.brand{color:#3be7ff;letter-spacing:.12em;text-transform:uppercase}.score{font-size:56px;margin:8px 0;color:#59f0b5}table{width:100%;border-collapse:collapse;margin:24px 0 40px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #26304c}th{color:#9eacc8}.state{padding:3px 8px;border-radius:99px;background:#202943}.warning,.missing{color:#ffbe55}.secure{color:#59f0b5}footer{margin-top:50px;color:#9eacc8}@media print{body{background:#fff;color:#172033}.brand,.score{color:#087d91}}</style></head><body><main><p class="brand">HeaderGuard · abyssnx</p><h1>Informe de seguridad HTTP</h1><p>${escapeHTML(report.source)} · ${escapeHTML(report.generated_at)}</p><div class="score">${report.analysis.score}/100 · ${escapeHTML(report.analysis.grade)}</div><p>${report.analysis.secure} correctas · ${report.analysis.warnings} mejorables · ${report.analysis.missing} ausentes</p><h2>Cabeceras evaluadas</h2><table><thead><tr><th>Cabecera</th><th>Estado</th><th>Valor</th><th>Recomendación</th></tr></thead><tbody>${rows}</tbody></table>${cookies}<footer>Generado con HeaderGuard by abyssnx · Este informe no sustituye una auditoría profesional.</footer></main></body></html>`;
}

document.querySelector("#download-html").addEventListener("click", () => {
  const report = exportableReport();
  if (!report) return;
  const blob = new Blob([reportHTML(report)], { type: "text/html;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `headerguard-${report.analysis.score}.html`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("Informe HTML descargado");
});

document.querySelector("#print-report").addEventListener("click", () => window.print());

document.querySelector("#copy-summary").addEventListener("click", async () => {
  if (!currentReport) return;
  const analysis = currentReport.analysis;
  const priorities = analysis.priorities.map((item) => `• ${item.name}: ${item.message}`).join("\n");
  const text = [
    `HeaderGuard — ${sourceLabel(currentReport)}`,
    `Puntuación: ${analysis.score}/100 (${analysis.grade})`,
    `${analysis.secure} correctas · ${analysis.warnings} mejorables · ${analysis.missing} ausentes`,
    priorities ? `\nPrioridades:\n${priorities}` : "\nSin acciones urgentes.",
    "\nGenerado con HeaderGuard by abyssnx",
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    showToast("Resumen copiado");
  } catch {
    showToast("El navegador no permitió copiar el resumen");
  }
});

document.querySelector("#copy-badge").addEventListener("click", async () => {
  if (!currentReport) return;
  const { score, grade } = currentReport.analysis;
  const color = grade === "A" ? "59f0b5" : grade === "B" ? "3be7ff" : grade === "C" ? "ffbe55" : "ff667d";
  const badge = `![HeaderGuard](https://img.shields.io/badge/HeaderGuard-${score}%2F100-${color}?style=for-the-badge&logo=shield)`;
  try {
    await navigator.clipboard.writeText(badge);
    showToast("Badge Markdown copiado");
  } catch {
    showToast("El navegador no permitió copiar el badge");
  }
});

document.querySelector("#server-type").addEventListener("change", updateConfiguration);

document.querySelector("#copy-config").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(document.querySelector("#config-output").textContent);
    showToast("Configuración copiada");
  } catch {
    showToast("El navegador no permitió copiar la configuración");
  }
});

document.querySelector("#download-config").addEventListener("click", () => {
  const server = document.querySelector("#server-type").value;
  const extensions = { nginx: "conf", apache: "conf", fastapi: "py", express: "js" };
  const blob = new Blob([document.querySelector("#config-output").textContent], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `headerguard-${server}.${extensions[server]}`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("Configuración descargada");
});

document.querySelector("#clear-history").addEventListener("click", () => {
  safeStorage(() => localStorage.removeItem(HISTORY_KEY));
  renderHistory();
  showToast("Historial local eliminado");
});

const themeToggle = document.querySelector("#theme-toggle");
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeToggle.textContent = theme === "light" ? "☀" : "☾";
  themeToggle.setAttribute("aria-label", theme === "light" ? "Activar tema oscuro" : "Activar tema claro");
}

const initialTheme = safeStorage(() => localStorage.getItem(THEME_KEY))
  || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
applyTheme(initialTheme);
themeToggle.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(next);
  safeStorage(() => localStorage.setItem(THEME_KEY, next));
});

renderHistory();
