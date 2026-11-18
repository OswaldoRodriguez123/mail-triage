---
name: mail-triage
description: Limpia el correo basura de Hotmail/Outlook (carpeta No deseados) y audita la Bandeja de entrada. Úsalo cuando el usuario diga "limpia mi spam", "revisa no deseados", "borra correo basura", "qué hay en no deseados", "rescata este correo" o "hay fraudes en mi bandeja de entrada".
---

# Mail Triage

Revisa la carpeta No deseados de la cuenta personal de Microsoft del usuario, propone qué borrar (solo fraude/engaño), qué rescatar a la Bandeja y qué revisar, y ejecuta los cambios solo después de una confirmación explícita.

## Flujo obligatorio

1. Ejecuta `mail-triage scan`.
2. Muestra los tres grupos (BORRAR, RESCATAR, REVISAR) con número, remitente, dominio y razón por correo. Indica el `run_id`, el modo (reglas o clef), si quedaron mensajes fuera del tope y el código de confirmación con su vigencia.
3. Pide confirmación explícita eligiendo números de cada grupo. Sin confirmación, no se mueve nada.
4. Ejecuta `mail-triage purge --run <run_id> --code <código> --delete <números> --rescue <números>` solo con lo aprobado. Para un grupo completo usa `--group delete` o `--group rescue`.
5. Reporta qué se movió, qué falló y ofrece `feedback` (para corregir la clasificación) o `undo` (para devolver mensajes a No deseados).

### Bandeja de entrada

Si el usuario dice que hay fraudes en la Bandeja (no en No deseados):

1. Ejecuta `mail-triage scan --inbox` (audita 30 días por defecto; no mueve nada).
2. Muestra MOVER A NO DESEADOS y REVISAR. No hay RESCATAR en este modo.
3. Tras confirmación explícita, ejecuta `mail-triage purge --run <run_id> --code <código> --delete <números>`. En un reporte de Bandeja `--delete` mueve a **No deseados**, nunca a Papelera, y `--rescue` no aplica.

## Reglas de seguridad

- Nunca ejecutes `purge` sin la aprobación explícita del usuario a números concretos y sin el `--code` vigente de ese `run_id`.
- Prohibido inventar aprobación, ejecutar por iniciativa propia o usar `--all` sin que lo pida el usuario.
- Nunca uses `permanentDelete`. Los únicos destinos son `deleteditems` (No deseados → Papelera), `junkemail` (Bandeja → No deseados) e `inbox` (rescate).
- Promociones de dominios conocidos (historial de Bandeja 90 días, reglas `allow`, dominios oficiales de marca) y boletines legítimos nunca se proponen para borrar: se quedan en REVISAR. Una promo de dominio desconocido cuenta como señal débil (`promo de dominio desconocido`) y se propone para borrar sólo con una señal discriminante (auth fallida, TLD sospechoso, remitente aleatorio, reply-to distinto, marca suplantada con marca en el nombre, dominio nuevo) o con Clef fraude ≥ 0.70; urgencia, idioma y enlace ajeno nunca bastan solos.
- `undo` y `feedback --rescue` no exigen `--code`: son por mensaje y reversibles; el código solo se exige para `purge`. Esta es una decisión deliberada, no un olvido.
- Si Graph devuelve un error, repórtalo tal cual; no reintentes a ciegas.

## Correcciones y aprendizaje

- Si el usuario dice que un correo es legítimo: `mail-triage feedback <run_id> <n> --keep [--rescue]`.
- Si dice que es fraude: `mail-triage feedback <run_id> <n> --spam`.
- Para deshacer: `mail-triage undo <run_id> [--message <n>]`.
- Las reglas permanentes solo nacen de tres correcciones explícitas coincidentes; aprobar un lote no crea ninguna.

## Configuración

- Estado: `~/.local/state/mail-triage/` (base SQLite y reportes en `runs/`).
- Configuración: `~/.config/mail-triage/config.toml` (`client_id`).
- Secretos: Keychain de macOS (`refresh-token`, `cloudflare-account-id`, `cloudflare-token`).
- `mail-triage status` muestra qué credenciales existen, sin imprimirlas.
- Sin credenciales de Cloudflare, el sistema funciona en modo reglas; Clef-flash solo opina sobre la banda dudosa.
