from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    weight: int
    purpose: str
    recommendation: str
    reference: str


RULES = (
    Rule(
        "strict-transport-security",
        20,
        "Obliga al navegador a usar HTTPS y reduce ataques de downgrade.",
        "max-age=31536000; includeSubDomains (añade preload solo tras comprobar requisitos).",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
    ),
    Rule(
        "content-security-policy",
        25,
        "Limita los orígenes desde los que se puede cargar contenido y mitiga XSS.",
        "Empieza con default-src 'self' y ajusta cada directiva a los recursos necesarios.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
    ),
    Rule(
        "x-content-type-options",
        10,
        "Evita que el navegador adivine tipos MIME.",
        "nosniff",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
    ),
    Rule(
        "x-frame-options",
        10,
        "Reduce el riesgo de clickjacking en navegadores antiguos.",
        "DENY o SAMEORIGIN; prioriza también frame-ancestors en CSP.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
    ),
    Rule(
        "referrer-policy",
        10,
        "Controla cuánta información de navegación se envía a otros sitios.",
        "strict-origin-when-cross-origin",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy",
    ),
    Rule(
        "permissions-policy",
        10,
        "Restringe APIs sensibles del navegador, como cámara o geolocalización.",
        "Desactiva lo que no uses, por ejemplo: camera=(), microphone=(), geolocation=().",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
    ),
    Rule(
        "cross-origin-opener-policy",
        5,
        "Aísla el contexto de navegación frente a ventanas de otros orígenes.",
        "same-origin (comprueba antes integraciones con ventanas externas).",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy",
    ),
    Rule(
        "cross-origin-resource-policy",
        5,
        "Limita qué otros orígenes pueden cargar los recursos de la respuesta.",
        "same-origin o same-site según el caso de uso.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy",
    ),
    Rule(
        "cross-origin-embedder-policy",
        5,
        "Exige recursos compatibles con aislamiento de origen cruzado.",
        "require-corp solo si todos los recursos externos son compatibles.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy",
    ),
)

SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


def _quality(name: str, value: str) -> tuple[str, str | None]:
    """Return a pragmatic quality signal without pretending to replace an audit."""
    lowered = value.lower()

    if name == "strict-transport-security":
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", lowered)
        if not match:
            return "warning", "Incluye una directiva max-age válida."
        if int(match.group(1)) < 31_536_000:
            return "warning", "El max-age es inferior al año recomendado."
    elif name == "content-security-policy":
        risky = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in lowered]
        if re.search(r"(?:^|[;\s])\*(?:[;\s]|$)", lowered):
            risky.append("*")
        if risky:
            return "warning", f"Revisa fuentes permisivas: {', '.join(risky)}."
        if "default-src" not in lowered and "script-src" not in lowered:
            return "warning", "Define al menos default-src o script-src."
    elif name == "x-content-type-options" and lowered != "nosniff":
        return "warning", "El único valor recomendado es nosniff."
    elif name == "x-frame-options" and lowered not in {"deny", "sameorigin"}:
        return "warning", "Usa DENY o SAMEORIGIN."
    elif name == "referrer-policy":
        policies = {item.strip() for item in lowered.split(",")}
        if not policies.intersection(SAFE_REFERRER_POLICIES):
            return "warning", "Usa una política restrictiva como strict-origin-when-cross-origin."
    elif name == "permissions-policy" and "*" in lowered:
        return "warning", "Evita permitir capacidades sensibles a todos los orígenes (*)."
    elif name == "cross-origin-opener-policy" and lowered not in {
        "same-origin",
        "same-origin-allow-popups",
    }:
        return "warning", "Valora same-origin para un aislamiento fuerte."
    elif name == "cross-origin-resource-policy" and lowered not in {
        "same-origin",
        "same-site",
    }:
        return "warning", "Usa same-origin o same-site cuando sea compatible."
    elif name == "cross-origin-embedder-policy" and lowered not in {
        "require-corp",
        "credentialless",
    }:
        return "warning", "Usa require-corp o credentialless cuando sea compatible."

    return "secure", None


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Normalize names and values, discarding unsafe control characters."""
    normalized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = raw_name.strip().lower()
        value = raw_value.strip()
        if name and not any(ord(char) < 32 and char != "\t" for char in name + value):
            normalized[name] = value
    return normalized


def analyze_cookies(headers: dict[str, str]) -> dict[str, object]:
    """Inspect cookie attributes without retaining or returning cookie values."""
    raw_cookies: list[str] = []
    for raw_name, raw_value in headers.items():
        if raw_name.strip().lower() == "set-cookie":
            raw_cookies.extend(line.strip() for line in raw_value.splitlines() if line.strip())

    cookies: list[dict[str, object]] = []
    for raw_cookie in raw_cookies:
        parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()[:128] or "(sin nombre)"
        attributes: dict[str, str | None] = {}
        for part in parts[1:]:
            key, separator, value = part.partition("=")
            attributes[key.strip().lower()] = value.strip().lower() if separator else None

        secure = "secure" in attributes
        http_only = "httponly" in attributes
        same_site = attributes.get("samesite")
        issues: list[str] = []
        if not secure:
            issues.append("Falta Secure")
        if not http_only:
            issues.append("Falta HttpOnly; confirma si JavaScript necesita acceder a ella")
        if same_site not in {"lax", "strict", "none"}:
            issues.append("Falta un atributo SameSite explícito")
        if same_site == "none" and not secure:
            issues.append("SameSite=None requiere Secure")

        lower_name = name.lower()
        if lower_name.startswith("__secure-") and not secure:
            issues.append("El prefijo __Secure- requiere Secure")
        if lower_name.startswith("__host-"):
            if not secure or attributes.get("path") != "/" or "domain" in attributes:
                issues.append("El prefijo __Host- requiere Secure, Path=/ y ningún Domain")

        cookies.append(
            {
                "name": name,
                "status": "secure" if not issues else "warning",
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site,
                "issues": issues,
            }
        )

    return {
        "count": len(cookies),
        "secure": sum(cookie["status"] == "secure" for cookie in cookies),
        "warnings": sum(cookie["status"] == "warning" for cookie in cookies),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
        "cookies": cookies,
    }


def analyze_headers(headers: dict[str, str]) -> dict[str, object]:
    normalized = normalize_headers(headers)
    results: list[dict[str, object]] = []
    score = 0

    for rule in RULES:
        value = normalized.get(rule.name)
        present = bool(value)
        status, issue = _quality(rule.name, value) if value else ("missing", None)
        earned = rule.weight if status == "secure" else max(0, rule.weight - 5) if present else 0
        score += earned
        results.append(
            {
                "name": rule.name,
                "present": present,
                "value": value,
                "purpose": rule.purpose,
                "recommendation": rule.recommendation,
                "weight": rule.weight,
                "earned": earned,
                "status": status,
                "issue": issue,
                "reference": rule.reference,
            }
        )

    grade = (
        "A"
        if score >= 90
        else "B"
        if score >= 75
        else "C"
        if score >= 55
        else "D"
        if score >= 35
        else "F"
    )
    priorities = [
        {
            "name": item["name"],
            "status": item["status"],
            "message": item["issue"] or item["recommendation"],
        }
        for item in results
        if item["status"] != "secure"
    ][:3]
    return {
        "score": score,
        "grade": grade,
        "present": sum(item["present"] for item in results),
        "secure": sum(item["status"] == "secure" for item in results),
        "warnings": sum(item["status"] == "warning" for item in results),
        "missing": sum(item["status"] == "missing" for item in results),
        "total": len(results),
        "priorities": priorities,
        "results": results,
        "cookies": analyze_cookies(headers),
    }


def parse_raw_headers(raw: str) -> dict[str, str]:
    if len(raw.encode("utf-8")) > 32_768:
        raise ValueError("El bloque de cabeceras supera el límite de 32 KB.")

    headers: dict[str, str] = {}
    lines = raw.replace("\r\n", "\n").split("\n")
    if lines and lines[0].upper().startswith("HTTP/"):
        lines = lines[1:]

    for line in lines:
        if not line.strip():
            continue
        if line[:1].isspace():
            raise ValueError("No se admiten cabeceras continuadas en varias líneas.")
        if ":" not in line:
            raise ValueError(f"Línea de cabecera no válida: {line[:80]}")
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or any(char.isspace() for char in name):
            raise ValueError("Nombre de cabecera no válido.")
        if name.lower() == "set-cookie":
            existing_name = next(
                (header_name for header_name in headers if header_name.lower() == "set-cookie"),
                None,
            )
            if existing_name:
                headers[existing_name] = f"{headers[existing_name]}\n{value.strip()}"
            else:
                headers[name] = value.strip()
        else:
            headers[name] = value.strip()

    if not headers:
        raise ValueError("Pega al menos una cabecera con el formato Nombre: valor.")
    return headers
