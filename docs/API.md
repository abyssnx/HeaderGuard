# API de HeaderGuard

La edición completa expone una API HTTP mediante FastAPI. Al ejecutar el proyecto localmente, la URL base es `http://127.0.0.1:8000` y la documentación interactiva está en `/api/docs`.

## Resumen

| Método | Ruta | Función |
| --- | --- | --- |
| `GET` | `/api/health` | Comprueba que el servicio responde |
| `POST` | `/api/analyze` | Analiza un bloque de cabeceras pegadas |
| `POST` | `/api/scan` | Escanea las cabeceras de una URL pública |

Las respuestas son JSON. Los errores utilizan el formato habitual de FastAPI:

```json
{
  "detail": "Descripción segura del error"
}
```

## Comprobar el servicio

```bash
curl http://127.0.0.1:8000/api/health
```

Respuesta:

```json
{
  "status": "ok"
}
```

## Analizar cabeceras pegadas

`POST /api/analyze` no realiza conexiones externas. Acepta un campo `headers` de hasta 32 KiB.

### curl

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"headers":"HTTP/2 200\ncontent-security-policy: default-src '\''self'\''\nstrict-transport-security: max-age=31536000; includeSubDomains\nx-content-type-options: nosniff"}'
```

### PowerShell

```powershell
$body = @{
    headers = @"
HTTP/2 200
content-security-policy: default-src 'self'
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
"@
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri 'http://127.0.0.1:8000/api/analyze' `
    -ContentType 'application/json' `
    -Body $body
```

La respuesta contiene `source`, las cabeceras públicas normalizadas y el objeto `analysis`. Cualquier campo `Set-Cookie` se elimina de `headers` después de analizar sus atributos.

## Escanear una URL

`POST /api/scan` recibe una URL completa de entre 8 y 2048 caracteres.

### curl

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### PowerShell

```powershell
Invoke-RestMethod `
    -Method Post `
    -Uri 'http://127.0.0.1:8000/api/scan' `
    -ContentType 'application/json' `
    -Body (@{ url = 'https://example.com' } | ConvertTo-Json)
```

La respuesta incluye:

```json
{
  "requested_url": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "redirects": [],
  "headers": {},
  "analysis": {
    "score": 0,
    "grade": "F",
    "present": 0,
    "missing": 9,
    "total": 9
  }
}
```

El ejemplo muestra un extracto: la respuesta real añade `secure`, `warnings`, `results`, `priorities` y `cookies` con el detalle del análisis.

## Límites y seguridad del escaneo

- Solo se admiten los esquemas HTTP y HTTPS.
- Solo se permiten los puertos 80 y 443.
- No se admiten credenciales ni fragmentos en la URL.
- Todos los resultados DNS deben ser direcciones públicas.
- La conexión se fija a una IP previamente validada para reducir DNS rebinding.
- Cada redirección se vuelve a validar; se permiten como máximo cuatro.
- El escáner calcula un presupuesto de 5 segundos y transmite el tiempo restante a cada conexión. La API aplica además un límite exterior de 7 segundos, que también cubre el fallback de `HEAD` a `GET`.
- Si `HEAD` no está permitido, se utiliza `GET` con un rango mínimo y una lectura limitada a 64 KiB.
- `/api/scan` admite 20 solicitudes por minuto y dirección cliente en una única instancia.

El limitador incluido funciona en memoria. Si despliegas varias instancias o necesitas límites persistentes, utiliza además un proxy o servicio de rate limiting compartido.

## Códigos de error habituales

| Código | Situación |
| ---: | --- |
| `400` | URL bloqueada, destino no público, redirección inválida o fallo seguro del escáner |
| `422` | JSON o bloque de cabeceras no válido |
| `429` | Límite de solicitudes superado |
| `504` | El escaneo agotó el tiempo disponible |

## Consideraciones de despliegue

HeaderGuard está pensado como proyecto educativo. Antes de publicarlo en internet, añade autenticación si corresponde, límites en el proxy inverso, registros sin datos sensibles y monitorización. No desactives las validaciones SSRF para permitir redes internas.
