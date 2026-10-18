(() => {
  "use strict";

  const RULES = __HEADERGUARD_RULES__;
  const COOKIE_REFERENCE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie";
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

  globalThis.HeaderGuardLite = Object.freeze({
    rules: RULES,
    parseRawHeaders,
    quality,
    analyzeCookies,
    analyzeHeaders,
  });
})();
