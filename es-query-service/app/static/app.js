// Состояние кластеров: кнопка в шапке, выпадающий список и статусы на страницах администрирования
(function () {
  const btn = document.getElementById("es-status");
  if (!btn) return;
  const dot = document.getElementById("es-dot");
  const label = document.getElementById("es-label");
  const menu = document.getElementById("clusters-menu");
  const listEl = document.getElementById("clusters-list");
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
  const paint = (badge, item) => {
    badge.textContent = item.ok ? `доступен · ${item.cluster} ${item.version}` : "недоступен";
    badge.className = "badge " + (item.ok ? "ok" : "err");
    badge.title = item.ok ? "" : item.error;
  };

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    menu.hidden = !menu.hidden;
    btn.setAttribute("aria-expanded", String(!menu.hidden));
  });
  document.addEventListener("click", (e) => { if (!menu.hidden && !menu.contains(e.target)) menu.hidden = true; });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") menu.hidden = true; });

  fetch("/api/status").then(r => r.json()).then(d => {
    const list = d.clusters || [];
    const ok = list.filter(c => c.ok).length;
    if (!list.length) {
      label.textContent = "Нет кластеров";
      dot.className = "dot err";
      listEl.textContent = "Нет доступных кластеров — обратитесь к администратору.";
    } else {
      label.textContent = list.length === 1 ? list[0].name : `Кластеры: ${ok} из ${list.length}`;
      dot.className = "dot " + (ok === list.length ? "ok" : ok ? "warn" : "err");
      listEl.className = "";
      listEl.innerHTML = list.map(c => `
        <div class="cluster-item">
          <span class="dot ${c.ok ? "ok" : "err"}"></span>
          <div>
            <div class="cluster-item-name">${esc(c.name)}</div>
            <div class="cluster-item-sub">${c.ok ? `доступен · ${esc(c.cluster)} · версия ${esc(c.version)}` : esc(c.error)}</div>
          </div>
        </div>`).join("");
    }
    list.forEach(c => document.querySelectorAll(`[data-cluster-status="${c.id}"]`).forEach(b => paint(b, c)));
    (d.keys || []).forEach(k => document.querySelectorAll(`[data-key-status="${k.id}"]`).forEach(b => paint(b, k)));
  }).catch(() => { label.textContent = "Кластеры: ?"; });
})();

// Тема: авто (как в системе) → тёмная → светлая; выбор запоминается
(function () {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const root = document.documentElement;
  const names = {auto: "как в системе", dark: "тёмная", light: "светлая"};
  const current = () => root.dataset.theme || "auto";
  const show = () => {
    const mode = current();
    btn.querySelectorAll("[data-theme-icon]").forEach(el => (el.hidden = el.dataset.themeIcon !== mode));
    btn.title = `Тема: ${names[mode]} (нажмите, чтобы сменить)`;
  };
  btn.addEventListener("click", () => {
    const next = {auto: "dark", dark: "light", light: "auto"}[current()];
    if (next === "auto") delete root.dataset.theme; else root.dataset.theme = next;
    try { next === "auto" ? localStorage.removeItem("theme") : localStorage.setItem("theme", next); } catch (e) {}
    show();
  });
  show();
})();

// Боковое меню: свернуть на компьютере, выезжающая панель на телефоне
(function () {
  const root = document.documentElement;
  const collapse = document.getElementById("collapse-btn");
  const toggle = document.getElementById("menu-toggle");
  const backdrop = document.getElementById("backdrop");
  if (collapse) collapse.addEventListener("click", () => {
    const collapsed = root.classList.toggle("sidebar-collapsed");
    collapse.title = collapsed ? "Развернуть меню" : "Свернуть меню";
    try { collapsed ? localStorage.setItem("sidebar", "collapsed") : localStorage.removeItem("sidebar"); } catch (e) {}
  });
  if (toggle) toggle.addEventListener("click", () => root.classList.toggle("sidebar-open"));
  if (backdrop) backdrop.addEventListener("click", () => root.classList.remove("sidebar-open"));
})();

// Поиск по задачам на главной
function initTaskSearch() {
  const input = document.getElementById("task-search");
  if (!input) return;
  const rows = Array.from(document.querySelectorAll(".task-row"));
  const empty = document.getElementById("search-empty");
  const apply = () => {
    const words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    rows.forEach(row => {
      const hit = words.every(w => row.dataset.search.includes(w));
      row.hidden = !hit;
      shown += hit;
    });
    if (empty) empty.hidden = shown > 0;
  };
  input.addEventListener("input", apply);
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
      e.preventDefault();
      input.focus();
    }
  });
}

// Копирование в буфер
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const input = document.querySelector(btn.dataset.copy);
  input.select();
  (navigator.clipboard ? navigator.clipboard.writeText(input.value) : Promise.reject())
    .catch(() => document.execCommand("copy"))
    .finally(() => { btn.textContent = "Скопировано"; setTimeout(() => (btn.textContent = "Копировать"), 1500); });
});

function isNdjsonPath(path) {
  return /(^|\/)(_msearch|_msearch\/template|_bulk)\/?$/.test(path.split("?")[0]);
}

function initTaskForm() {
  const form = document.getElementById("task-form");
  const body = document.getElementById("body");
  const state = document.getElementById("json-state");
  const path = form.elements["path"];

  // Показываем блоки, относящиеся к выбранному режиму
  function applyMode() {
    const mode = form.querySelector("input[name=mode]:checked").value;
    form.querySelectorAll("[data-mode]").forEach(el => {
      const on = el.dataset.mode === mode;
      el.hidden = !on;
      el.querySelectorAll("button, input, select").forEach(i => (i.disabled = !on));
    });
  }
  form.querySelectorAll("input[name=mode]").forEach(r => r.addEventListener("change", applyMode));
  applyMode();

  // Галочки доставки
  form.querySelectorAll("[data-toggle]").forEach(cb => {
    const sec = form.querySelector(`[data-section="${cb.dataset.toggle}"]`);
    const apply = () => (sec.hidden = !cb.checked);
    cb.addEventListener("change", apply);
    apply();
  });

  form.querySelectorAll("[data-cron]").forEach(a => a.addEventListener("click", (e) => {
    e.preventDefault();
    form.elements["cron"].value = a.dataset.cron;
  }));

  // Проверка JSON на лету
  function check() {
    const text = body.value.trim();
    if (!text) { state.textContent = "без тела"; state.className = "hint"; return true; }
    try {
      if (isNdjsonPath(path.value)) {
        text.split("\n").filter(l => l.trim()).forEach(l => JSON.parse(l));
        state.textContent = "✓ NDJSON корректен";
      } else {
        JSON.parse(text);
        state.textContent = "✓ JSON корректен";
      }
      state.className = "hint ok-text";
      return true;
    } catch (err) {
      state.textContent = "✗ " + err.message;
      state.className = "hint err-text";
      return false;
    }
  }
  body.addEventListener("input", check);
  path.addEventListener("input", check);
  check();

  document.getElementById("fmt-json").addEventListener("click", () => {
    if (!check()) return;
    const text = body.value.trim();
    if (!text) return;
    if (isNdjsonPath(path.value)) {
      body.value = text.split("\n").filter(l => l.trim()).map(l => JSON.stringify(JSON.parse(l))).join("\n");
    } else {
      body.value = JSON.stringify(JSON.parse(text), null, 2);
    }
  });

  // Tab в редакторе вставляет отступ
  body.addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    e.preventDefault();
    const s = body.selectionStart;
    body.setRangeText("  ", s, body.selectionEnd, "end");
  });
}

// Ожидание завершения запуска
function pollRun(id) {
  const initial = document.getElementById("run-status").dataset.status;
  const tick = () => fetch(`/runs/${id}/status`).then(r => r.json()).then(d => {
    const sending = d.webhook_status && d.webhook_status.startsWith("Отправ");
    if (d.status !== initial || (!sending && initial !== "running")) location.reload();
    else setTimeout(tick, 1500);
  }).catch(() => setTimeout(tick, 5000));
  setTimeout(tick, 1000);
}
