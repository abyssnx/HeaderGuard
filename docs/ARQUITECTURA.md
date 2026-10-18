# Arquitectura de HeaderGuard

HeaderGuard ofrece dos ediciones que comparten reglas y modelo de puntuación, pero tienen límites de confianza distintos.

## Vista general

~~~mermaid
flowchart LR
    U[Persona usuaria] --> L[Lite · archivo local]
    U --> F[Completa · FastAPI]
    L --> J[Analizador JavaScript]
    F --> P[Analizador Python]
    F --> S[Escáner remoto]
    S --> V[Validación URL, DNS e IP]
    V --> W[Sitio público]
    J --> R[Informe y recomendaciones]
    P --> R
~~~

## Componentes

| Componente | Responsabilidad |
| --- | --- |
| `HeaderGuard-Lite.html` | Edición autónoma preparada para distribución |
| `standalone/` | Fuentes HTML, CSS y JavaScript mantenibles de Lite |
| `scripts/build_standalone.py` | Genera Lite e inserta reglas y hashes CSP |
| `app/analyzer.py` | Parser, reglas, puntuación y análisis de cookies |
| `app/scanner.py` | Resolución segura y conexión remota protegida |
| `app/main.py` | API FastAPI, límites de entrada y rate limiting |
| `app/static/` | Interfaz de la edición completa |
| `tests/` | Pruebas unitarias, seguridad, paridad y navegador |

## Edición Lite

Lite ejecuta todo en el navegador:

1. La persona pega una respuesta HTTP.
2. JavaScript normaliza las cabeceras.
3. El analizador aplica las nueve reglas.
4. La interfaz genera puntuación, prioridades y exportaciones.
5. El historial guarda únicamente un resumen en el almacenamiento local.

No existe backend, no hay escaneo remoto y la política CSP utiliza `connect-src 'none'`.

### Generación determinista

`HeaderGuard-Lite.html` no se mantiene manualmente. El generador:

- Importa las reglas desde `app.analyzer.RULES`.
- Inserta las fuentes de `standalone/`.
- Calcula los hashes SHA-256 de la política CSP.
- Produce siempre el mismo archivo para las mismas entradas.

La integración continua ejecuta:

~~~bash
python scripts/build_standalone.py --check
~~~

Si las fuentes cambian sin regenerar el archivo autónomo, la comprobación falla.

## Edición completa

FastAPI sirve la interfaz y tres endpoints:

- `GET /api/health`: estado del servicio.
- `POST /api/analyze`: análisis de cabeceras pegadas.
- `POST /api/scan`: escaneo de una URL pública.

El modo manual no realiza conexiones externas. El modo remoto pasa por el escáner protegido antes de llegar al analizador compartido.

## Flujo del escaneo remoto

~~~mermaid
sequenceDiagram
    participant C as Cliente
    participant A as API
    participant S as Escáner
    participant D as DNS
    participant W as Web pública

    C->>A: POST /api/scan
    A->>A: Validar JSON y rate limit
    A->>S: scan_url(url)
    S->>S: Validar esquema, host y puerto
    S->>D: Resolver todas las direcciones
    D-->>S: IPv4 / IPv6
    S->>S: Exigir que todas sean públicas
    S->>W: Conectar a una IP validada
    W-->>S: Estado y cabeceras
    S->>S: Revalidar cada redirección
    S-->>A: Resultado normalizado
    A->>A: Analizar y eliminar Set-Cookie
    A-->>C: JSON del informe
~~~

## Defensa frente a SSRF

El escáner aplica varias capas:

1. Acepta únicamente HTTP/HTTPS y los puertos 80/443.
2. Rechaza credenciales, fragmentos y hosts locales.
3. Normaliza nombres internacionales mediante IDNA.
4. Resuelve el dominio y exige que todas las IP sean globales públicas.
5. Conecta directamente a una IP ya validada para reducir DNS rebinding.
6. Conserva `Host`, SNI y la comprobación TLS del dominio solicitado.
7. Valida de nuevo cada destino de redirección.
8. Limita redirecciones, tiempo total, lectura y frecuencia.

Esta protección reduce el riesgo, pero no convierte el servicio en un proxy de propósito general. No debe desactivarse para acceder a redes internas.

## Datos y privacidad

| Dato | Lite | Completa |
| --- | --- | --- |
| Cabeceras pegadas | Memoria del navegador | Memoria del proceso durante la petición |
| Valores de cookies | Se descartan | Se descartan |
| Historial | Resumen local | Resumen local del frontend |
| Cuerpos remotos | No aplica | No se almacenan |
| Informes | Solo al exportarlos | Solo al exportarlos |

La API elimina `Set-Cookie` de la colección pública después de analizar sus atributos.

## Límites de confianza

HeaderGuard comprueba cabeceras y heurísticas conocidas. No analiza:

- Lógica de negocio, autenticación o autorización.
- Código fuente del servidor.
- Vulnerabilidades XSS, SQLi o CSRF de forma activa.
- Compatibilidad completa de una CSP con cada aplicación.
- Infraestructura situada detrás del destino público.

Las recomendaciones deben adaptarse y probarse antes de desplegarlas.

## Controles de calidad

La suite comprueba:

- Reglas, puntuación, cookies y parser.
- Bloqueo de redes privadas y casos SSRF.
- Redirecciones y conexiones fijadas a IP.
- Paridad entre los analizadores Python y JavaScript.
- Generación determinista de Lite.
- Recorridos reales de escritorio y móvil con Chromium.
- Lint y cobertura mínima del backend.

GitHub Actions ejecuta estas verificaciones en cada cambio.
