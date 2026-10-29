/* The local application freezes the message and sends it. Thunderbird must not. */

function addressOf(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(addressOf).filter(Boolean).join(", ");
  return value.email || value.id || "";
}

async function notice(message) {
  await browser.notifications.create({
    type: "basic",
    title: "GWyl Mail",
    message,
  });
}

browser.compose.onBeforeSend.addListener(async (tab, details) => {
  const attachments = details.attachments || [];
  const copies = addressOf(details.cc) || addressOf(details.bcc);
  if (attachments.length || copies) {
    await notice("Les copies et les pièces jointes ne sont pas encore envoyées par GWyl. L'envoi est annulé.");
    return { cancel: true };
  }
  let response;
  try {
    response = await fetch("http://127.0.0.1:8765/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-GWyl-Client": "1" },
      body: JSON.stringify({
        from: addressOf(details.from),
        to: addressOf(details.to),
        subject: details.subject || "",
        body: details.plainTextBody || details.body || "",
        allow_degraded: false,
      }),
    });
  } catch (error) {
    await notice("L'application locale ne répond pas. L'envoi est annulé.");
    return { cancel: true };
  }
  if (!response.ok) {
    await notice("GWyl n'a pas envoyé le message. L'envoi Thunderbird est annulé.");
    return { cancel: true };
  }
  await notice("Message envoyé par GWyl.");
  return { cancel: true };
});
