# Política de seguridad

## Versiones compatibles

| Versión | Soporte |
| --- | --- |
| 1.3.x | Sí |
| Anteriores | Solo la versión más reciente recibe correcciones |

## Reportar una vulnerabilidad

No publiques detalles explotables en una incidencia pública.

Utiliza un [aviso privado de seguridad](https://github.com/abyssnx/HeaderGuard/security/advisories/new) e incluye:

- Descripción y componente afectado.
- Pasos mínimos de reproducción.
- Impacto estimado.
- Versión o commit probado.
- Propuesta de mitigación, si existe.

Se intentará confirmar la recepción en un plazo de 72 horas. No se garantiza una recompensa económica.

## Alcance

Son especialmente relevantes:

- Formas de eludir las validaciones SSRF.
- Acceso a redes privadas, loopback o metadatos cloud.
- DNS rebinding o redirecciones no validadas.
- Exposición de valores de cookies o datos pegados.
- Ejecución de scripts no autorizados en cualquiera de las interfaces.

Los fallos de configuración de una web analizada no son vulnerabilidades de HeaderGuard.

## Uso responsable

HeaderGuard es una herramienta educativa, no un sustituto de una auditoría profesional. Escanea únicamente sistemas propios o para los que tengas autorización. Evita incluir datos personales o secretos en un informe compartido.
