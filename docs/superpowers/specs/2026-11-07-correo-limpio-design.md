# Correo Limpio — Diseño

Fecha: 2026-11-07
Estado: borrador para aprobación

## 1. Intención y por qué

El buzón de Hotmail del usuario recibe demasiado correo basura en la carpeta **No deseados**, pero de vez en cuando cae ahí correo legítimo y se pierde entre el ruido. El usuario quiere decirle al agente "limpia mi spam" y que:

1. se borre lo que es spam de verdad,
2. se rescate lo que parece legítimo,
3. lo dudoso no se toque y se le muestre,
4. el sistema aprenda de sus correcciones con el tiempo.

La herramienta vive dentro de OpenCode como una **skill** que llama a un CLI local. Se dispara desde el chat, no hay que abrir otra app.

### Hallazgos que definen el diseño

- Los ejemplos reales del buzón (captura del 2026-11-07) son detectables casi todos con reglas: suplantación de marca (Netflix desde `brainstormingyourliiife.net`), remitentes aleatorios (`TjTmsHecFCrflaZ@fjbb.zensdfisbs...`), el sello "No verificado" de Outlook (fallo DMARC), urgencia genérica ("Last Chance", "Expired Account"), y phishing en portugués contra un usuario hispanohablante.
- Por eso la IA es la **segunda opinión** para la cola dudosa, no el motor principal. Esto mantiene el costo casi en cero y hace el sistema explicable: cada decisión trae su razón.
- `jevmail` (open source) valida el enfoque de clasificación con preguntas tipadas, pero es solo Gmail y de solo lectura; no se reutiliza su app, solo la forma de preguntar.

## 2. Objetivos

- Escanear la carpeta No deseados y producir tres grupos: **borrar**, **rescatar**, **revisar**, cada uno con razón por correo.
- **Borrar solo fraude y engaño**: suplantación, phishing, estafa, enlaces maliciosos. La publicidad y los boletines legítimos no se borran, aunque no se hayan pedido.
- Ejecutar el borrado solo tras confirmación explícita del usuario en el chat.
- Mover lo borrado a la **Papelera** (recuperable), nunca borrado permanente.
- Mover lo rescatado a la **Bandeja de entrada**.
- Aprender de las correcciones: dominios/remitentes permitidos y bloqueados, persistentes entre corridas.
- Funcionar con **reglas solamente** si no hay credenciales de Cloudflare; Clef-flash es opcional.
- Costo de infraestructura: $0. Clasificación: $0 dentro del tier gratuito de Cloudflare.

## 3. No objetivos

- No es un cliente de correo ni una app web.
- No ordena la Bandeja de entrada ni compite con SaneBox.
- No soporta Gmail, iCloud ni IMAP genérico en v1.
- No hay daemon ni cron en v1; se dispara desde el chat.
- No borra permanentemente, no vacía la Papelera, no toca otras carpetas.
- No lee adjuntos, no responde, no envía.
- No crea reglas dentro de Outlook; todo el aprendizaje es local.

## 4. Anti-objetivos (así se considera un fracaso)

- Borrar un correo legítimo sin que el usuario lo haya aprobado.
- Borrar algo sin posibilidad de recuperarlo.
- Ejecutar un borrado sin confirmación explícita (un "sí" del usuario, no un default).
- Mandar cuerpos completos de correo a un tercero.
- Requerir un servicio de pago para funcionar.
- Fallar en silencio: si Graph rechaza algo, hay que decirlo y detenerse.

## 5. Restricciones

- Cuenta **personal** de Microsoft (hotmail.com / outlook.com). Se usa Microsoft Graph con permisos delegados `Mail.ReadWrite` y `offline_access`; el registro de app en Azure es gratuito y lo hace el usuario una sola vez.
- Flujo **device code** de cliente público: sin secreto, sin redirect URI. Requiere activar "Allow public client flows" en el registro.
- Tenant `consumers` para cuentas personales.
- No se piden permisos de contactos ni de calendario.
- El refresh token se guarda en el **Keychain de macOS** (`security`), nunca en texto plano en el repo.
- Python 3.14 ya instalado; **solo biblioteca estándar** (`urllib`, `sqlite3`, `email`, `json`, `argparse`, `unittest`). Sin dependencias externas.
- **Cloudflare Workers AI** con Clef-flash (`@cf/cloudflare/clef-flash`) en el **tier gratuito**: 10,000 neuronas/día, sin plan de pago y sin cobro sorpresa. El modelo tiene retención de datos cero. `CLOUDFLARE_ACCOUNT_ID` y API token viven en el Keychain, nunca en el repo.
- El usuario debe poder auditar todo: reporte por corrida en JSON y CSV.

## 6. Enfoques considerados

**A. Skill de OpenCode + CLI local sobre Graph (elegido).**
Registro de app una vez, token en Keychain, reglas deterministas + Clef-flash opcional (Cloudflare, gratis), SQLite de aprendizaje. Control total del criterio y del borrado, se dispara desde el chat, costo casi nulo. Costo real: construirlo y mantenerlo.

**B. SaneBox (~$7/mes).**
Cero código y aprende solo, pero no distingue "spam real" con el criterio del usuario, no borra de No deseados, no se dispara desde el chat y lee todo el correo. Se descarta como solución principal; queda como alternativa si el usuario prefiere pagar.

**C. Adaptar `jevmail`.**
Su UI e integración con Jev son útiles, pero su diseño es Gmail + solo lectura; portarlo a Graph con escritura cuesta más que A y da una app web que el usuario no pidió. Se descarta; se conserva la idea de preguntas tipadas, que Clef-flash implementa directamente.

## 7. Cómo funciona

### 7.1 Flujo de una corrida

```
correo-limpio scan [--max 200] [--all] [--include-reviewed]
correo-limpio purge --run <id> --code <código> \
    (--delete 1,4,7 | --group delete) (--rescue 2 | --group rescue)
correo-limpio feedback <run> <n> --keep|--spam [--rescue]
correo-limpio undo <run> [--message <n>]
```

1. **Traer**: `GET /me/mailFolders/junkemail/messages` paginado, con `$select` acotado (id, subject, from, sender, replyTo, receivedDateTime, bodyPreview, internetMessageHeaders, hasAttachments, isRead, internetMessageId). Se piden páginas hasta juntar `--max` mensajes **no vistos antes** (los ya decididos o ya marcados como revisados se saltan), así el spam viejo se drena en corridas sucesivas en vez de quedar tapado por los nuevos. `--all` ignora el tope; `--include-reviewed` vuelve a mostrar los que ya salieron en `revisar`. El reporte avisa si quedaron mensajes fuera del tope.
2. **Evidencia**: remitente, dominio, nombre visible, reply-to, resultado de autenticación, asunto, primeros ~400 caracteres de texto, dominios de los enlaces, idioma.
3. **Reglas**: puntaje 0..1 con veto. Ver 7.2.
4. **Clef-flash (opcional)**: solo para los que caen en la banda dudosa. Ver 7.3.
5. **Grupos**: `borrar` (>= 0.85, sin veto **y con al menos una señal de fraude**), `rescatar` (<= 0.30, señal positiva de legitimidad y sin ser promoción), `revisar` (resto, incluidos promos y boletines legítimos, que se quedan en No deseados).
6. **Reporte**: tabla legible + JSON/CSV en `~/.local/state/correo-limpio/runs/<fecha>/`. Cada correo lleva un número (`n`). El reporte incluye `run_id` y un **código de 6 caracteres** derivado del hash del run, que caduca a los 60 minutos. El hash cubre el conjunto exacto de mensajes y buckets, para que `purge` no pueda ejecutar otra cosa que lo escaneado.
7. **Purge**: actúa solo sobre los números o grupos que el usuario apruebe, no sobre el run completo por defecto. Mueve a `deleteditems` lo aprobado como borrar y a `inbox` lo aprobado como rescatar; reintenta una vez por error; se detiene y reporta si Graph falla de forma sistémica. Exige `--code`.
8. **Undo**: `undo <run>` revierte la corrida completa; `undo <run> --message <n>` revierte un solo movimiento. Mueve de vuelta a `junkemail` lo que siga existiendo y degrada la regla automática que lo haya causado.
9. **Feedback**: `feedback <run> <n> --keep` permite rescatar ese mensaje ya mismo con `--rescue`, sin esperar otra corrida; `--spam` refuerza el bloqueo. Las reglas y el rescate inmediato se aplican solo al mensaje indicado, nunca al lote.

### 7.2 Reglas (motor principal)

Puntaje aditivo, acotado a [0,1]:

| Señal | Peso | Nota |
|---|---|---|
| Suplantación de marca | +0.35 | el nombre visible contiene una marca conocida y el dominio real no pertenece a esa marca |
| Fallo de autenticación | +0.30 | `dmarc=fail` / `spf=fail` / `dkim=fail` en `Authentication-Results` (o el "No verificado" de Outlook si viene en cabeceras) |
| Remitente aleatorio | +0.25 | localpart o dominio con alta entropía, sin vocales, largo anómalo, dígitos mezclados |
| Reply-To distinto | +0.20 | dominio del Reply-To ≠ dominio del From |
| Enlaces sospechosos | +0.15 | dominio destino ≠ dominio del remitente, IP cruda, acortadores |
| Urgencia genérica | +0.10 | "last chance", "expired", "confirm your", "parcel", "renewal", "prize", emojis 🚩❗ |
| Idioma que no cuadra | +0.10 | pt/it/fr/de detectado cuando el usuario espera es/en |
| Dominio recién creado | +0.10 | RDAP (`rdap.org`, gratis), edad < 30 días, cacheado en SQLite |
| Dominio en lista de bloqueo | +0.25 | regla aprendida o del usuario |
| Dominio visto en la Bandeja | −0.40 | señal fuerte de legitimidad (últimos 90 días) |

**Guardia de fraude**: el puntaje solo no alcanza para borrar. `borrar` exige al menos una **señal de fraude explícita**: suplantación de marca, fallo de autenticación, enlace malicioso, Reply-To discrepante o dominio en lista de bloqueo. Urgencia, idioma o dominio nuevo, por sí solos, solo llevan a `revisar`. Así un boletín legítimo de un dominio nuevo nunca se borra. Una regla de bloqueo puesta explícitamente por el usuario fuerza `borrar` (salvo veto): es el punto de aprender de sus correcciones.

**Vetos** (impiden `borrar`, fuerzan como máximo `revisar`): remitente o dominio en lista de permitidos, o dominio presente en la Bandeja. Un correo con veto nunca se borra automáticamente. El veto **no rescata por sí solo**: un dominio permitido que empiece a mandar phishing no debe terminar en la Bandeja. Para rescatar se exige además puntaje bajo (<= 0.30) y señal positiva de legitimidad (autenticación correcta o remitente conocido).

Calibración esperada con los ejemplos reales: el falso Netflix suma 0.35 + 0.30 + 0.10 = 0.75–1.0 → borrar. Un boletín raro de un dominio nuevo suma ~0.45 → revisar (lo decide Clef-flash o el usuario). Un recibo de un dominio ya visto en Bandeja queda con veto → nunca se borra.

Las listas de marcas y palabras viven en `rules/data/*.txt` para poder ajustarlas sin tocar código.

### 7.3 Clef-flash en Cloudflare Workers AI (segunda opinión, opcional)

- Modelo `@cf/cloudflare/clef-flash` (9B, decisiones tipadas, contexto 24,576 tokens, retención de datos cero), por REST:
  `POST https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/cloudflare/clef-flash`
  con `Authorization: Bearer <api_token>` y cuerpo `{"model": "clef-flash", "state": ..., "questions": {...}}`.
- Credenciales: `CLOUDFLARE_ACCOUNT_ID` y API token con permiso de Workers AI, guardados en el Keychain (`correo-limpio-cloudflare`).
- **Costo: $0.** El tier gratuito da 10,000 neuronas/día. Clef-flash consume 3,455 neuronas por millón de tokens de entrada y no cobra salida: equivalen a ~2.9M tokens/día. Una corrida de 100 correos (~70k tokens) gasta ~240 neuronas, menos del 3% del cupo. Si se agota, la API falla y la corrida sigue en modo reglas; en el plan gratis no hay cobro sorpresa.
- Sin credenciales, el modo reglas sigue siendo funcional y los dudosos van a `revisar`.
- Preguntas por correo (una sola llamada, todas en paralelo del lado del modelo):
  - `choice` **categoria**: fraude/phishing | promoción no solicitada | notificación legítima | persona | boletín suscrito.
  - `noul` **fraude**: "¿Es un intento de fraude o suplantación?"
  - `noul` **esperado**: "¿El destinatario probablemente espera o necesita este correo?"
- Respuesta: `result.answers`; `noul` llega como probabilidad y `choice` con la opción elegida y probabilidades por opción.
- Regla de decisión: `P(fraude) >= 0.90` → borrar; `P(esperado) >= 0.70` y `P(fraude) < 0.30` y categoría distinta de promoción/boletín → rescatar; si no, revisar. **Promoción o boletín nunca se borra ni se rescata por esta vía**: se queda en No deseados y se muestra en `revisar`.
- Se envía solo: remitente, dominio, asunto, 400 caracteres de texto, dominios de enlaces y resultado de autenticación. Nunca el cuerpo completo, adjuntos ni otros correos. Cloudflare declara retención cero para este modelo.

### 7.4 Aprendizaje

SQLite en `~/.local/state/correo-limpio/state.db`:

- `domain_rules(domain, verdict allow|block, source user|auto, hits, updated_at)`
- `sender_rules(address, verdict, source, hits, updated_at)`
- `decisions(run_id, message_id, sender, domain, subject_hash, bucket, reason, decided_at, undone_at)`
- `inbox_senders(domain, address, last_seen)` — foto de la Bandeja, solo lectura
- `domain_age(domain, created_at, checked_at)` — caché de RDAP

Aprendizaje concreto:

1. `feedback --spam` crea/refuerza regla de bloqueo para remitente y dominio.
2. `feedback --keep` crea/refuerza regla de permitido y el correo se puede rescatar.
3. `undo` degrada la regla automática que causó el borrado.
4. **Solo el feedback explícito promueve reglas automáticas.** Con 3 `feedback` del mismo veredicto y el mismo dominio, en mensajes distintos y corridas distintas, la regla pasa a `auto` y aplica en corridas futuras. Aprobar un lote con `purge` se registra en `decisions`, pero **no** crea reglas `auto`: un solo "sí" no debe bloquear un dominio para siempre.
5. Cada scan refresca `inbox_senders` (máx. 500 remitentes recientes) para que un remitente legítimo gane veto solo.

### 7.5 Seguridad y control

- `scan` es siempre de solo lectura.
- `purge` exige `--run <id>`, `--code` (de un scan de los últimos 60 minutos) y una selección explícita de mensajes o grupos. El `run_id` incluye un hash del conjunto de decisiones; si algo cambió, se rechaza.
- El código es fricción deliberada, **no una frontera de seguridad**: el agente lo ve en el reporte. La frontera real es que nada se ejecuta sin que el usuario lo pida en el chat. La skill tiene prohibido inventar una aprobación o ejecutar por iniciativa propia.
- Borrar = mover a Papelera. Rescatar = mover a Bandeja. Nunca `permanentDelete`.
- Tope de 200 mensajes por corrida; `--all` lo levanta solo si el usuario lo pide explícitamente.
- Bitácora por corrida con id de mensaje, asunto, remitente, bucket, razón y resultado de la acción.
- Si un movimiento falla, se registra y se continúa; si falla la autenticación o falla 3 veces seguidas, se aborta y se reporta.
- Nada de credenciales en el repo: `.gitignore` cubre `config.toml`, `*.db`, `runs/`.

### 7.6 Skill de OpenCode

`~/.config/opencode/skills/correo-limpio/SKILL.md`, con disparadores tipo "limpia mi spam", "revisa no deseados", "borra el correo basura". Comportamiento obligatorio:

1. Correr `scan` y presentar los tres grupos con remitente, asunto y razón.
2. Preguntar antes de ejecutar. Nunca ejecutar `purge` sin un "sí" explícito.
3. Ejecutar `purge --run <id> --code <código> --delete ... --rescue ...` solo para lo aprobado, o `--group delete|rescue` si el usuario aprobó el grupo completo.
4. Reportar qué se movió y ofrecer `feedback`/`undo` para correcciones.
5. Si falta login o el registro de Azure, explicar los pasos y no intentar atajos.

## 8. Estructura del proyecto

```
~/repos/correo-limpio/
  pyproject.toml                 # metadatos; sin dependencias; entry point del CLI
  correo_limpio/
    __main__.py                  # python3 -m correo_limpio
    cli.py                       # scan | purge | feedback | undo | login | status
    auth.py                      # device code, refresh, Keychain
    graph.py                     # cliente HTTP mínimo de Graph
    fetch.py                     # traer No deseados + remitentes de Bandeja
    evidence.py                  # parseo de cabeceras, enlaces, idioma
    rules.py                     # motor de puntaje + vetos
    classifier.py                # Clef-flash opcional (Cloudflare)
    store.py                     # SQLite, migraciones simples
    report.py                    # tabla, JSON, CSV
    rules/data/                  # marcas, palabras, acrónimos
  tests/                         # unittest, fixtures sintéticos
  docs/superpowers/specs/2026-11-07-correo-limpio-design.md
  README.md                      # registro en Azure paso a paso + uso
```

## 9. Configuración e instalación (una vez)

1. Registro en Azure: app "correo-limpio", cuentas personales, cliente público, permisos delegados `Mail.ReadWrite` + `offline_access`, sin secreto.
2. `correo-limpio login` → muestra código y URL; el usuario autoriza en el navegador; el refresh token queda en Keychain.
3. (Opcional) credenciales de Cloudflare en Keychain con `correo-limpio login --cloudflare` (account ID + API token con permiso Workers AI).
4. `correo-limpio scan` con `--dry-run` implícito.

## 10. Decisiones tomadas por el agente (para revisar)

- **Rescatar va a la Bandeja de entrada**, no a una carpeta aparte: el problema declarado es que el correo válido se pierde; moverlo a otra carpeta no lo resuelve.
- **La foto de remitentes de la Bandeja se toma de los últimos 90 días** y alimenta el veto. Es lectura, no requiere permisos extra.
- **Clef-flash arranca apagado** hasta que el usuario decida conectar Cloudflare; el sistema debe ser útil solo con reglas.
- **El CLI se llama `correo-limpio`** y la carpeta del proyecto igual, en `~/repos/`.
- **Sin dependencias externas**: menos superficie de fallo y de actualización.
- **La aprobación es por subconjunto**: el usuario puede aprobar solo algunos números o solo un grupo; `purge` nunca asume "todo".
- **El scan salta lo ya visto** y reporta cuántos quedan fuera; así el spam viejo se drena en corridas sucesivas.
- **`undo` y `feedback` son por mensaje** cuando hace falta, no solo por corrida.
- **Una regla automática nace solo de feedback explícito**, nunca de aprobar un lote.
- **Los fixtures de prueba son sintéticos**, construidos con los patrones de la captura; no se versiona correo real.
- **Clef-flash en Cloudflare reemplaza a Jev** (pedido del usuario, 2026-11-07): mismas preguntas tipadas, tier gratuito de 10,000 neuronas/día y retención de datos cero.
- **Solo fraude y engaño se borra** (decisión del usuario, 2026-11-07): promos y boletines legítimos se quedan en No deseados y se muestran en `revisar`, nunca en `borrar`.

## 11. Lo que queda al constructor

- Contenido inicial de las listas de marcas y palabras (empezar con 30–50 marcas y 40 términos, en español e inglés).
- Umbrales finos de cada regla después de la primera corrida real.
- Redacción exacta de las preguntas a Clef-flash y su calibración con los ejemplos reales.
- Formato de la tabla del reporte y del resumen para el chat.
- Caché de RDAP: TTL y manejo de dominios sin RDAP.
- Pruebas de integración contra un buzón real (manuales, no en CI).

## 12. Criterios de aceptación

- `scan` no modifica nada y muestra los tres grupos con razones.
- Los seis patrones de la captura de referencia, reproducidos como fixtures sintéticos, se clasifican como `borrar` o `revisar`, nunca como `rescatar`; ninguno se borra sin `purge`.
- Un boletín o promo legítimo, incluso de un dominio nuevo, nunca cae en `borrar`: como máximo va a `revisar`.
- Los seis fixtures: suplantación de Netflix, "Cloud Billing" con dominio ajeno, remitente aleatorio con asunto de urgencia, falso débito bancario en portugués, falso Medicare y oferta de viaje con cuerpo vacío.
- Un remitente presente en la Bandeja nunca cae en `borrar`, y el veto no basta para rescatarlo.
- `purge` sin `--code`, con un `run_id` viejo, o sin selección explícita, no hace nada.
- Aprobar solo un subconjunto mueve solo ese subconjunto.
- `scan` reporta si quedaron mensajes fuera del tope y no repite los ya vistos.
- `undo --message` revierte un solo correo sin tocar el resto de la corrida.
- `feedback --keep` impide que ese remitente se vuelva a borrar.
- Aprobar un lote no crea reglas `auto`; tres feedback coincidentes sí.
- Toda la suite de `unittest` pasa sin red ni credenciales.
- Sin credenciales de Cloudflare, el sistema sigue funcionando en modo reglas.
