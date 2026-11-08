# Mail Triage

CLI local y skill de OpenCode que revisan la carpeta **No deseados** de una cuenta personal de Microsoft (Hotmail/Outlook).

- **Borra solo fraude y engaño**: suplantación, phishing, estafa y enlaces maliciosos. Promociones y boletines legítimos nunca se borran.
- **Rescata a la Bandeja lo que parece legítimo**, como un recibo o una notificación que el usuario definitivamente espera.
- **Lo dudoso se queda**: va a `REVISAR` y se muestra con su razón.
- **Aprende de las correcciones**: dominios permitidos y bloqueados, con reglas automáticas solo después de tres correcciones explícitas coincidentes.
- Todo es local: Python con biblioteca estándar, SQLite y Keychain. Sin servicios de pago.

## Requisitos

- macOS con Python 3.11 o superior.
- Una cuenta personal de Microsoft (hotmail.com, outlook.com o cuenta personal).
- Una app registrada en Azure (gratis), una sola vez.
- Opcional: una cuenta de Cloudflare para la segunda opinión con Clef-flash.

## Configuración

### 1. Registrar la app en Azure

1. Entra a **Azure Portal → Microsoft Entra ID → App registrations → New registration**.
2. Nombre: `mail-triage`.
3. **Supported account types**: *Accounts in any organizational directory and personal Microsoft accounts* (cuentas personales).
4. **Redirect URI**: ninguna (flujo de código de dispositivo).
5. **API permissions** (permisos delegados):
   - `Microsoft Graph` → `Mail.ReadWrite`
   - `Microsoft Graph` → `offline_access`
6. Guarda el **Application (client) ID**.
7. En **Authentication**, activa **Allow public client flows** (falla el flujo de código de dispositivo si está apagado).

### 2. Guardar el client_id

```toml
# ~/.config/mail-triage/config.toml
client_id = "tu-client-id"
max_per_run = 200
inbox_lookback_days = 90
```

### 3. Autorizar Graph

```bash
pip install -e .   # si quieres el comando corto
mail-triage login
```

o sin instalar:

```bash
python3 -m mail_triage login
```

### 4. (Opcional) Cloudflare Workers AI

Clef-flash (`@cf/cloudflare/clef-flash`) opina solo sobre los correos en la banda dudosa, dentro del tier gratuito de 10.000 neuronas/día y con retención de datos cero. Sin credenciales, el motor de reglas sigue funcionando.

```bash
mail-triage login --cloudflare
```

Se piden el **account ID** y un API token con permiso de Workers AI. Se guardan en el Keychain.

### 5. (Opcional) Instalar la skill de OpenCode

```bash
./scripts/install-skill.sh
```

Esto enlaza `skills/mail-triage/` en `~/.config/opencode/skills/`.

## Uso

```bash
# Revisar sin mover nada: imprime los tres grupos y un código de 6 caracteres.
mail-triage scan

# Ejecutar solo lo aprobado del último reporte (código válido 60 minutos).
mail-triage purge --run <run_id> --code <código> --delete 1,4,7 --rescue 2

# Grupo completo: borrar todo lo que está en BORRAR.
mail-triage purge --run <run_id> --code <código> --group delete

# Deshacer: devolver mensajes de una corrida a No deseados.
mail-triage undo <run_id> [--message <n>]

# Corregir la clasificación de un mensaje y aprender de ello.
mail-triage feedback <run_id> <n> --keep [--rescue]   # es legítimo
mail-triage feedback <run_id> <n> --spam               # es fraude

# Estado y credenciales (sin imprimir valores).
mail-triage status
```

Cada corrida deja un reporte en `~/.local/state/mail-triage/runs/<run_id>/` en JSON y CSV.

## Qué hace y qué no

**Hace**

- Escanea No deseados por lotes (tope 200 por defecto), sin repetir mensajes ya revisados.
- Califica cada correo con reglas deterministas: suplantación de marca, fallo de autenticación, remitente aleatorio, reply-to distinto, enlace a dominio ajeno, urgencia, idioma distinto de español/inglés, TLD sospechoso y antigüedad del dominio (RDAP). Cada decisión trae su razón.
- Usa Clef-flash como segunda opinión solo para la banda dudosa.
- Mueve lo aprobado a **Papelera** o a **Bandeja de entrada** mediante Microsoft Graph.
- Aprende dominios permitidos y bloqueados en SQLite: un veto nunca se borra, una regla de bloqueo confirmada fuerza borrar.
- Degrada automáticamente una regla automática cuando la corrida que la causó se deshace.

**No hace**

- No borra permanentemente (`permanentDelete` nunca se llama) y no vacía la Papelera.
- No toca ninguna otra carpeta que `deleteditems` e `inbox`.
- No envía, responde ni lee adjuntos; no es un cliente de correo.
- `undo` y `feedback --rescue` no exigen `--code`: son operaciones por mensaje y reversibles; el código de confirmación solo se exige para `purge`, que es el único que mueve lotes. Esta es una decisión deliberada (ver spec §7.5).
- No manda cuerpos completos de correo a terceros: a Cloudflare solo van remitente, asunto, 400 caracteres de texto, dominios de enlaces y autenticación.
- No crea reglas dentro de Outlook; todo el aprendizaje es local.

## Migración desde el nombre anterior

Antes se llamaba `correo-limpio`. Si venías de ahí, el código sigue encontrando
tu configuración, estado y secretos viejos automáticamente. Para dejar todo
en el nuevo nombre:

```bash
mv ~/.config/correo-limpio ~/.config/mail-triage
mv ~/.local/state/correo-limpio ~/.local/state/mail-triage
security find-generic-password -s correo-limpio -a refresh-token -w  # cópialo y guárdalo con servicio mail-triage
```

## Desinstalar

```bash
rm ~/.config/opencode/skills/mail-triage
rm -rf ~/.local/state/mail-triage ~/.config/mail-triage
security delete-generic-password -s mail-triage -a refresh-token
security delete-generic-password -s mail-triage -a cloudflare-account-id
security delete-generic-password -s mail-triage -a cloudflare-token
```

Borrar el estado elimina las reglas aprendidas y la sesión; los correos movidos permanecen en Papelera o Bandeja.
