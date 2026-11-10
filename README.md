# Mail Triage

[![tests](https://github.com/OswaldoRodriguez123/mail-triage/actions/workflows/tests.yml/badge.svg)](https://github.com/OswaldoRodriguez123/mail-triage/actions/workflows/tests.yml)

Local CLI and OpenCode skill that reviews your **junk mail** folder and sorts
every message into **DELETE**, **RESCUE** or **REVIEW**, with explicit
confirmation before anything moves.

```text
Corrida 20261110T120000-a1b2c3 · modo scan
Válido hasta 2026-11-10 13:00 UTC

BORRAR (2)
  1. [0.97] Microsoft Support · micros0ft-support.top
     Your account will be suspended in 24 hours
     razón: suplantación de marca: microsoft; dominio con TLD sospechoso; urgencia; fallo de autenticación SPF/DKIM
  2. [0.91] Facturación · facturacion.cl
     Factura 2026-118 · Servicios Digitales
     razón: reply-to distinto del remitente; enlace a dominio ajeno; dominio registrado hace 3 días

RESCATAR (2)
  3. [0.12] Tienda Ejemplo · tienda-ejemplo.cl
     Tu pedido fue enviado
     razón: dominio permitido
  4. [0.18] Barbería Centro · barberia-centro.cl
     Confirmación de reserva
     razón: remitente conocido; enlace al mismo dominio

REVISAR (2)
  5. [0.48] Revista Ejemplo · revista-ejemplo.com
     Newsletter semanal
     razón: boletín con baja sospechosa; remitente nuevo
  6. [0.52] Contacto · gmail.com
     Re: propuesta
     razón: asunto genérico; remitente aleatorio
```

- **Only fraud and scams get deleted**: impersonation, phishing, scams and
  malicious links. Legitimate promotions and newsletters are never deleted.
- **Legit-looking mail is rescued to the Inbox**, such as a receipt or a
  notification the user is actually waiting for.
- **Doubtful mail stays**: it goes to `REVIEW` with its reason.
- **It learns from corrections**: allowed and blocked domains, with automatic
  rules only after three matching explicit corrections.
- Everything is local: Python standard library, SQLite and Keychain. No paid
  services.

### Providers

The engine works against a `MailProvider` interface. Only the **Microsoft
Outlook** backend (Microsoft Graph) is implemented today, but the architecture
is ready for Gmail, IMAP or others without touching the classifier.

| Provider | Status |
| --- | --- |
| Outlook / Microsoft Graph | ✅ implemented |
| Gmail | 🔜 next (only `providers/gmail.py` is missing) |
| Generic IMAP | 🔮 future |

Every command accepts `--provider` (defaults to `outlook`).

## Requirements

- macOS with Python 3.11 or newer.
- An account on a supported provider (Microsoft Outlook today).
- For Outlook: an app registered in Azure (free), one time only.
- Optional: a Cloudflare account for the Clef-flash second opinion.

## Setup

### 1. Outlook provider (Microsoft Graph)

To use the Outlook backend you need to register an app in Azure:

1. Go to **Azure Portal → Microsoft Entra ID → App registrations → New registration**.
2. Name: `mail-triage`.
3. **Supported account types**: *Accounts in any organizational directory and
   personal Microsoft accounts*.
4. **Redirect URI**: none (device code flow).
5. **API permissions** (delegated):
   - `Microsoft Graph` → `Mail.ReadWrite`
   - `Microsoft Graph` → `offline_access`
6. Save the **Application (client) ID**.
7. In **Authentication**, enable **Allow public client flows** (the device code
   flow fails if this is off).

### 2. Store the client_id

```toml
# ~/.config/mail-triage/config.toml
client_id = "your-client-id"
max_per_run = 200
inbox_lookback_days = 90
```

### 3. Authorize the provider

```bash
pip install -e .   # for the short command
mail-triage login --provider outlook
```

or without installing:

```bash
python3 -m mail_triage login
```

### 4. (Optional) Cloudflare Workers AI

Clef-flash (`@cf/cloudflare/clef-flash`) only weighs in on mail in the doubtful
band, inside the free tier of 10,000 neurons/day and with zero data retention.
Without credentials the rule engine still works.

```bash
mail-triage login --cloudflare
```

It asks for the **account ID** and an API token with the Workers AI permission.
Both are stored in the Keychain.

### 5. (Optional) Install the OpenCode skill

```bash
./scripts/install-skill.sh
```

This links `skills/mail-triage/` into `~/.config/opencode/skills/`.

## Usage

```bash
# Review without moving anything: prints the three groups and a 6-character code.
mail-triage scan --provider outlook

# Apply only what was approved in the last report (code valid for 60 minutes).
mail-triage purge --run <run_id> --code <code> --delete 1,4,7 --rescue 2 --provider outlook

# Whole group: delete everything in DELETE.
mail-triage purge --run <run_id> --code <code> --group delete

# Undo: move messages from a run back to Junk.
mail-triage undo <run_id> [--message <n>]

# Correct a classification and learn from it.
mail-triage feedback <run_id> <n> --keep [--rescue]   # it is legit
mail-triage feedback <run_id> <n> --spam               # it is fraud

# Status and credentials (never prints values).
mail-triage status
```

Each run leaves a report in `~/.local/state/mail-triage/runs/<run_id>/` as JSON
and CSV.

## What it does and does not do

**Does**

- Scans Junk in batches (200 by default) without repeating messages already
  reviewed.
- Scores every email with deterministic rules: brand impersonation,
  authentication failure, random sender, mismatched reply-to, link to a foreign
  domain, urgency, language other than Spanish/English, suspicious TLD and
  domain age (RDAP). Every decision carries its reason.
- Uses Clef-flash as a second opinion only for the doubtful band.
- Moves approved mail to **Trash** or **Inbox** through the active provider.
- Learns allowed and blocked domains in SQLite: a veto is never removed, and a
  confirmed block rule forces deletion.
- Automatically downgrades an automatic rule when the run that caused it is
  undone.
- Caches model verdicts per domain (valid for 4 days with runs) to avoid
  re-querying what was already evaluated.
- Automatically rescues mail from allowed domains to the Inbox without calling
  the model.

**Does not**

- Permanently delete (`permanentDelete` is never called) or empty the Trash.
- Touch folders other than the provider's Trash and Inbox equivalents.
- Send, reply or read attachments; it is not a mail client.
- `undo` and `feedback --rescue` do not require `--code`: they are per-message
  and reversible. The confirmation code is only required for `purge`, the only
  command that moves batches.
- Send full email bodies to third parties: Cloudflare only receives sender,
  subject, 400 characters of text, link domains and authentication results.
- Create rules inside the provider; all learning is local.

## Uninstall

```bash
rm ~/.config/opencode/skills/mail-triage
rm -rf ~/.local/state/mail-triage ~/.config/mail-triage
security delete-generic-password -s mail-triage -a refresh-token
security delete-generic-password -s mail-triage -a cloudflare-account-id
security delete-generic-password -s mail-triage -a cloudflare-token
```

Deleting the state removes the learned rules and the session; moved emails stay
in Trash or Inbox.

## License

MIT. See [LICENSE](LICENSE).
