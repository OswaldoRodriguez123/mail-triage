---
name: correo-limpio
description: Limpia el correo basura de Hotmail/Outlook (carpeta No deseados). Úsalo cuando el usuario diga "limpia mi spam", "revisa no deseados", "borra correo basura", "qué hay en no deseados" o "rescata este correo".
---

# Correo Limpio

Revisa la carpeta No deseados de la cuenta personal de Microsoft del usuario, propone qué borrar (solo fraude/engaño), qué rescatar a la Bandeja y qué revisar, y ejecuta los cambios solo después de una confirmación explícita.

## Flujo obligatorio

1. Ejecuta `correo-limpio scan`.
2. Muestra los tres grupos (BORRAR, RESCATAR, REVISAR) con número, remitente, dominio y razón por correo. Indica el `run_id`, el modo (reglas o clef), si quedaron mensajes fuera del tope y el código de confirmación con su vigencia.
3. Pide confirmación explícita eligiendo números de cada grupo. Sin confirmación, no se mueve nada.
4. Ejecuta `correo-limpio purge --run <run_id> --code <código> --delete <números> --rescue <números>` solo con lo aprobado. Para un grupo completo usa `--group delete` o `--group rescue`.
5. Reporta qué se movió, qué falló y ofrece `feedback` (para corregir la clasificación) o `undo` (para devolver mensajes a No deseados).

## Reglas de seguridad

- Nunca ejecutes `purge` sin la aprobación explícita del usuario a números concretos y sin el `--code` vigente de ese `run_id`.
- Prohibido inventar aprobación, ejecutar por iniciativa propia o usar `--all` sin que lo pida el usuario.
- Nunca uses `permanentDelete` ni toques otra carpeta que `deleteditems` e `inbox`.
- Promociones y boletines legítimos nunca se proponen para borrar ni para rescatar: se quedan en No deseados y quedan en REVISAR.
- `undo` y `feedback --rescue` no exigen `--code`: son por mensaje y reversibles; el código solo se exige para `purge`. Esta es una decisión deliberada, no un olvido.
- Si Graph devuelve un error, repórtalo tal cual; no reintentes a ciegas.

## Correcciones y aprendizaje

- Si el usuario dice que un correo es legítimo: `correo-limpio feedback <run_id> <n> --keep [--rescue]`.
- Si dice que es fraude: `correo-limpio feedback <run_id> <n> --spam`.
- Para deshacer: `correo-limpio undo <run_id> [--message <n>]`.
- Las reglas permanentes solo nacen de tres correcciones explícitas coincidentes; aprobar un lote no crea ninguna.

## Configuración

- Estado: `~/.local/state/correo-limpio/` (base SQLite y reportes en `runs/`).
- Configuración: `~/.config/correo-limpio/config.toml` (`client_id`).
- Secretos: Keychain de macOS (`refresh-token`, `cloudflare-account-id`, `cloudflare-token`).
- `correo-limpio status` muestra qué credenciales existen, sin imprimirlas.
- Sin credenciales de Cloudflare, el sistema funciona en modo reglas; Clef-flash solo opina sobre la banda dudosa.
