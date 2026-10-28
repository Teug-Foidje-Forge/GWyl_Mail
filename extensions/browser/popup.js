document.getElementById("go").onclick = async () => {
  const out = document.getElementById("out");
  const file = document.getElementById("file").files[0];
  if (!file) {
    out.textContent = "Choisissez un fichier .eml";
    return;
  }
  const body = new FormData();
  body.append("eml", file, "message.eml");
  if (document.getElementById("deg").checked) body.append("allow_degraded", "1");
  try {
    const res = await fetch("http://127.0.0.1:8765/api/check", {
      method: "POST",
      headers: { "X-GWyl-Client": "1" },
      body,
    });
    const data = await res.json();
    out.textContent = (res.ok ? "Accepté\n" : "Refusé\n") + JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Interface injoignable. Lancez : gwyl-mail ui\n" + err;
  }
};
