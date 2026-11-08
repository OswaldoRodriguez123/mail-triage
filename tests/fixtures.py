"""Synthetic messages built from the patterns in the user's real Junk folder.

Nothing here comes from a real mailbox: addresses, domains and bodies are
invented. Keep it that way.
"""


def _msg(
    message_id,
    subject,
    name,
    address,
    body,
    auth=None,
    reply_to=None,
    received="2026-11-06T10:00:00Z",
    has_attachments=False,
):
    message = {
        "id": message_id,
        "internetMessageId": f"<{message_id}@example.test>",
        "subject": subject,
        "from": {"emailAddress": {"name": name, "address": address}},
        "body": {"content": body},
        "receivedDateTime": received,
        "hasAttachments": has_attachments,
        "internetMessageHeaders": (
            [{"name": "Authentication-Results", "value": auth}] if auth else []
        ),
    }
    if reply_to:
        message["replyTo"] = [{"emailAddress": {"address": reply_to}}]
    return message


def netflix_phish():
    return _msg(
        "m1",
        "Last Chance: Confirm Your Renewal",
        "Netflix",
        "support@brainstormingyourliiife.net",
        "Your Netflix subscription expired. Confirm your payment now at "
        "https://netflix-verify.test/login or lose access.",
        auth=(
            "spf=fail smtp.mailfrom=brainstormingyourliiife.net; dkim=none; "
            "dmarc=fail header.from=brainstormingyourliiife.net"
        ),
    )


def soda_random():
    return _msg(
        "m2",
        "The 14X baking soda ritual ending suddenly 🚩❗",
        "Soda Tips",
        "k7x2q9m4p8z1@soda-tips.test",
        "The 14X baking soda ritual ends tonight. See what everyone is "
        "talking about at https://soda-tips.test/ritual",
        auth="spf=pass smtp.mailfrom=soda-tips.test; dkim=pass; dmarc=pass header.from=soda-tips.test",
    )


def cloud_billing():
    return _msg(
        "m3",
        "Your monthly cloud statement is ready",
        "Cloud Provider Billing",
        "billing@cloudprovider.test",
        "Your statement for October is available in the billing console. "
        "No action is required.",
        auth="spf=pass smtp.mailfrom=cloudprovider.test; dkim=pass; dmarc=pass header.from=cloudprovider.test",
    )


def vivo_pt():
    return _msg(
        "m4",
        "Sua fatura está em atraso",
        "Vivo",
        "cobranca@vivo-seguro.test",
        "Sua fatura vencida. Você precisa atualizar o pagamento agora. "
        "Não perca o prazo. Acesse https://vivo-portal.test/pagar para "
        "evitar a suspensão.",
        auth="spf=fail smtp.mailfrom=vivo-seguro.test; dkim=none; dmarc=fail header.from=vivo-seguro.test",
    )


def medicare():
    return _msg(
        "m5",
        "Your Medicare benefits are expiring",
        "Medicare Support",
        "m3d1c4r3x9z7@medicare-alerts.test",
        "Verify your Medicare account today to keep your benefits. "
        "https://medicare-alerts.test/verify",
        auth="spf=pass smtp.mailfrom=medicare-alerts.test; dkim=pass; dmarc=pass header.from=medicare-alerts.test",
    )


def travel_empty():
    return _msg(
        "m6",
        "Take advantage of your trip",
        "Travel Deals",
        "travel@traveldeals.test",
        "Take advantage of this offer for your next trip.",
        auth="spf=pass smtp.mailfrom=traveldeals.test; dkim=pass; dmarc=pass header.from=traveldeals.test",
    )


def promo_newsletter():
    return _msg(
        "m7",
        "50% off this week",
        "Shop Deals",
        "deals@shop.test",
        "Huge sale this week only. Unsubscribe at any time.",
        auth="spf=pass smtp.mailfrom=shop.test; dkim=pass; dmarc=pass header.from=shop.test",
    )


def sanitized_receipt():
    return _msg(
        "m8",
        "Your receipt from Store",
        "Store Receipts",
        "receipts@store.test",
        "Thanks for your order. Your receipt is attached to this message.",
        auth="spf=pass smtp.mailfrom=store.test; dkim=pass; dmarc=pass header.from=store.test",
        has_attachments=True,
    )
