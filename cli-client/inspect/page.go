package inspect

// pageHTML — kuzatuv sahifasi.
//
// Bitta faylda va tashqi bog'liqliksiz: inspector lokal vosita va
// u CDN ga chiqishi yoki qo'shimcha fayl talab qilishi kerak emas.
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>cc01 inspector</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 0; display: grid; grid-template-rows: auto 1fr; height: 100vh; }
  header { padding: .6rem 1rem; border-bottom: 1px solid #8884;
           display: flex; gap: 1rem; align-items: center; }
  header b { font-weight: 600; }
  #count { opacity: .6; }
  button { font: inherit; padding: .2rem .6rem; }
  main { display: grid; grid-template-columns: 22rem 1fr; overflow: hidden; }
  #list { overflow-y: auto; border-right: 1px solid #8884; }
  .row { padding: .45rem .8rem; border-bottom: 1px solid #8882; cursor: pointer; }
  .row:hover { background: #8881; }
  .row.on { background: #8883; }
  .m { font-weight: 600; margin-right: .4rem; }
  .s2 { color: #2a2; } .s3 { color: #29a; } .s4 { color: #c82; }
  .s5 { color: #c33; } .s0 { color: #888; }
  .u { opacity: .85; word-break: break-all; }
  .t { float: right; opacity: .5; font-size: .85em; }
  #detail { overflow-y: auto; padding: 1rem; }
  #detail h3 { margin: 1.2rem 0 .4rem; font-size: .95rem; }
  #detail h3:first-child { margin-top: 0; }
  pre { background: #8881; padding: .6rem; overflow-x: auto;
        white-space: pre-wrap; word-break: break-all; margin: 0; }
  .empty { opacity: .5; padding: 2rem; text-align: center; }
  .warn { color: #c82; }
</style>
<header>
  <b>cc01 inspector</b>
  <span id="count">0 ta so'rov</span>
  <button onclick="clearAll()">tozalash</button>
</header>
<main>
  <div id="list"><div class="empty">so'rov kutilmoqda…</div></div>
  <div id="detail"><div class="empty">chapdan so'rov tanlang</div></div>
</main>
<script>
const items = new Map();
let selected = null;

function statusClass(e) {
  if (!e.status) return "s0";
  return "s" + Math.floor(e.status / 100);
}

function render() {
  const list = document.getElementById("list");
  const all = [...items.values()].sort((a, b) => b.id - a.id);
  document.getElementById("count").textContent = all.length + " ta so'rov";

  if (!all.length) {
    list.innerHTML = '<div class="empty">so\'rov kutilmoqda…</div>';
    return;
  }

  list.innerHTML = "";
  for (const e of all) {
    const row = document.createElement("div");
    row.className = "row" + (e.id === selected ? " on" : "");
    row.onclick = () => { selected = e.id; render(); detail(e); };

    const status = e.status || "—";
    row.innerHTML =
      '<span class="m">' + esc(e.method) + '</span>' +
      '<span class="' + statusClass(e) + '">' + status + '</span>' +
      '<span class="t">' + (e.duration_ms ?? 0) + 'ms</span>' +
      '<div class="u">' + esc(e.url) + '</div>';
    list.appendChild(row);
  }
}

function headers(h) {
  if (!h) return "(yo'q)";
  return Object.entries(h).map(([k, v]) => k + ": " + v.join(", ")).join("\n");
}

function detail(e) {
  const parts = [];
  parts.push("<h3>So'rov</h3><pre>" +
    esc(e.method + " " + e.url + " " + e.proto + "\nHost: " + e.host + "\n" +
        headers(e.request_headers)) + "</pre>");

  if (e.request_body) {
    parts.push("<h3>So'rov tanasi" +
      (e.request_truncated ? ' <span class="warn">(qirqilgan)</span>' : "") +
      "</h3><pre>" + esc(e.request_body) + "</pre>");
  }

  if (e.error) {
    parts.push('<h3 class="warn">Xato</h3><pre>' + esc(e.error) + "</pre>");
  } else {
    parts.push("<h3>Javob — " + e.status + "</h3><pre>" +
      esc(headers(e.response_headers)) + "</pre>");
    if (e.response_body) {
      parts.push("<h3>Javob tanasi" +
        (e.response_truncated ? ' <span class="warn">(qirqilgan)</span>' : "") +
        "</h3><pre>" + esc(e.response_body) + "</pre>");
    }
  }

  document.getElementById("detail").innerHTML = parts.join("");
}

function esc(s) {
  return String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
}

function add(e) { items.set(e.id, e); render(); }

async function clearAll() {
  await fetch("/api/clear", { method: "POST" });
  items.clear(); selected = null; render();
  document.getElementById("detail").innerHTML =
    '<div class="empty">chapdan so\'rov tanlang</div>';
}

fetch("/api/exchanges").then(r => r.json()).then(list => {
  (list || []).forEach(e => items.set(e.id, e));
  render();
});

const stream = new EventSource("/api/stream");
stream.onmessage = ev => add(JSON.parse(ev.data));
</script>
`
