/* Thirsty Quench Balance Sheet — authenticated frontend */

const TITLES = {
  dashboard: "Dashboard",
  daily: "Daily Records",
  baggers: "Bagger Pay",
  expenses: "Occasional Expenses",
  materials: "Raw Materials",
  weekly: "Weekly Cost",
  users: "User Management",
  settings: "Settings",
  account: "My Account",
};

const SUBS = {
  dashboard: "Operations overview",
  daily: "Production & sales log",
  baggers: "Worker bag payments",
  expenses: "Occasional costs",
  materials: "Raw material purchases",
  weekly: "Cost per bag by week",
  users: "Admin & worker accounts",
  settings: "Business configuration",
  account: "Profile & password",
};

const FORMS = {
  daily: {
    titleAdd: "Add daily record",
    titleEdit: "Edit daily record",
    fields: [
      { name: "date", label: "Date", type: "date", required: true },
      { name: "week", label: "Week (auto if blank)", type: "number" },
      { name: "produced", label: "Produced (bags)", type: "number", step: "1" },
      { name: "sold_out", label: "Sold out", type: "number", step: "1" },
      { name: "asanteman", label: "Asanteman sales", type: "number", step: "1" },
      { name: "sold_inside", label: "Sold inside", type: "number", step: "1" },
      { name: "fuel", label: "Fuel (₵)", type: "number", step: "0.01" },
      { name: "new_debt", label: "New debt (₵)", type: "number", step: "0.01" },
      { name: "debt_paid", label: "Debt paid (₵)", type: "number", step: "0.01" },
    ],
  },
  baggers: {
    titleAdd: "Add bags produced",
    titleEdit: "Edit bags produced",
    fields: [
      { name: "date", label: "Date", type: "date", required: true },
      { name: "worker", label: "Name", type: "text", required: true, placeholder: "e.g. Angelo" },
      { name: "bags_done", label: "Bags produced", type: "number", step: "1", required: true },
      { name: "rate", label: "Rate (₵)", type: "number", step: "0.01" },
      { name: "paid", label: "Mark as paid", type: "checkbox" },
    ],
  },
  expenses: {
    titleAdd: "Add expense",
    titleEdit: "Edit expense",
    fields: [
      { name: "date", label: "Date", type: "date", required: true },
      {
        name: "description",
        label: "Description",
        type: "text",
        required: true,
        placeholder: "e.g. Pelleting",
      },
      { name: "amount", label: "Amount (₵)", type: "number", step: "0.01", required: true },
      { name: "notes", label: "Notes", type: "textarea" },
    ],
  },
  materials: {
    titleAdd: "Add raw material",
    titleEdit: "Edit raw material",
    fields: [
      { name: "date", label: "Date", type: "date", required: true },
      { name: "item", label: "Item", type: "text", required: true, placeholder: "e.g. Roll, Packing" },
      { name: "amount", label: "Amount (₵)", type: "number", step: "0.01", required: true },
      { name: "notes", label: "Notes", type: "textarea" },
    ],
  },
  users: {
    titleAdd: "Add user",
    titleEdit: "Edit user",
    fields: [
      { name: "display_name", label: "Full name", type: "text", required: true },
      { name: "username", label: "Username", type: "text", required: true },
      {
        name: "role",
        label: "Role",
        type: "select",
        required: true,
        options: [
          { value: "admin", label: "Admin" },
          { value: "driver", label: "Driver" },
          { value: "bagger", label: "Bagger" },
        ],
      },
      { name: "password", label: "Password", type: "password", required: true },
      { name: "active", label: "Active account", type: "checkbox" },
    ],
  },
};

let state = null;
let usersList = [];
let modalCtx = { collection: null, id: null, mode: null };
let isAdmin = !!window.TQ_IS_ADMIN;
let role = window.TQ_ROLE || (isAdmin ? "admin" : "worker");
let currentUser = window.TQ_USER || null;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function money(n, cur = "₵") {
  const v = Number(n) || 0;
  const sign = v < 0 ? "-" : "";
  return `${sign}${cur}${Math.abs(v).toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  })}`;
}

function num(n) {
  return (Number(n) || 0).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function moneyClass(n) {
  const v = Number(n) || 0;
  if (v > 0) return "money-pos";
  if (v < 0) return "money-neg";
  return "";
}

function toast(msg, kind = "ok") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${kind}`;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => {
    el.hidden = true;
  }, 2800);
}

async function api(path, opts = {}) {
  const mutating = ["POST","PUT","PATCH","DELETE"].includes((opts.method || "GET").toUpperCase());
  let csrf = window.TQ_CSRF || "";
  if (!csrf) {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) csrf = meta.content;
  }
  const headers = {
    "Content-Type": "application/json",
    ...(csrf && mutating ? { "X-CSRF-Token": csrf } : {}),
    ...(opts.headers || {}),
  };
  const res = await fetch(path, {
    headers,
    credentials: "same-origin",
    ...opts,
  });
  if (res.status === 401) {
    window.location.href = "/login";
    throw new Error("Login required");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText || "Request failed");
  return data;
}

async function refresh() {
  state = await api("/api/data");
  isAdmin = !!state.is_admin;
  currentUser = state.user || currentUser;
  applyRoleUI();
  renderAll();
  if (isAdmin) await loadUsers();
}

function cur() {
  return state?.settings?.currency || "₵";
}

function applyRoleUI() {
  $$(".admin-only").forEach((el) => {
    el.hidden = !isAdmin;
  });
  $$(".admin-col").forEach((el) => {
    el.hidden = !isAdmin;
  });
  $$(".driver-col").forEach((el) => {
    el.hidden = role !== "driver";
  });
  $$(".bagger-col").forEach((el) => {
    el.hidden = role !== "bagger";
  });
  document.body.classList.toggle("role-admin", isAdmin);
  document.body.classList.toggle("role-driver", role === "driver");
  document.body.classList.toggle("role-bagger", role === "bagger");

  if (currentUser) {
    $("#userName").textContent = currentUser.display_name || currentUser.username;
    const roleLabel = isAdmin ? "Administrator" : role === "driver" ? "Driver" : role === "bagger" ? "Bagger" : "Worker";
    $("#userRole").textContent = roleLabel;
    $("#userAvatar").textContent = (currentUser.display_name || currentUser.username || "?").charAt(0).toUpperCase();
  }
}

function setTab(name) {
  if (!isAdmin) {
    if (role === "bagger" && !["dashboard", "baggers", "account"].includes(name)) {
      toast("Baggers can access baggers and account only", "err");
      return;
    }
    if (role === "driver" && !["dashboard", "daily", "baggers", "account"].includes(name)) {
      toast("Drivers can access daily and account only", "err");
      return;
    }
  }
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  $("#pageTitle").textContent = TITLES[name] || name;
  $("#pageSub").textContent = SUBS[name] || "";
  $(".sidebar")?.classList.remove("open");
  if (name === "users" && isAdmin) loadUsers();
  if (name === "account") renderAccount();
}

function renderAll() {
  if (!state) return;
  const s = state.summary;
  const c = cur();

  $("#brandName").textContent = state.settings.business_name || "Thirsty Quench";

  if (isAdmin && s.cash_in_hand != null) {
    const cashEl = $("#sidebarCash");
    if (cashEl) {
      cashEl.textContent = money(s.cash_in_hand, c);
      cashEl.classList.toggle("neg", s.cash_in_hand < 0);
    }
  }

  // Hero
  const heroes = [
    metric("Bag inventory", num(s.inventory), "good"),
    metric("Total produced", num(s.total_produced), ""),
    metric("Total sold", num(s.total_sold), ""),
    metric("Unpaid baggers", money(s.unpaid_baggers, c), s.unpaid_baggers > 0 ? "warn" : "good"),
  ];
  if (isAdmin) {
    heroes[0] = metric(
      "Cash in hand",
      money(s.cash_in_hand, c),
      s.cash_in_hand >= 0 ? "accent" : "bad"
    );
    heroes[2] = metric("Total sales", money(s.total_sales, c), "");
  }
  $("#heroCards").innerHTML = heroes.join("");

  const L = state.latest;
  $("#latestDate").textContent = L?.date || "—";
  const latestRows = L
    ? [
        row("Produced", num(L.produced)),
        row("Sold out", num(L.sold_out)),
        row("Asanteman", num(L.asanteman)),
        row("Sold inside", num(L.sold_inside)),
        row("Fuel", money(L.fuel, c)),
      ]
    : null;
  if (L && isAdmin && L.calculated_cash != null) {
    latestRows.push(row("Calculated cash", money(L.calculated_cash, c), true, L.calculated_cash < 0));
  }
  $("#latestStats").innerHTML = latestRows
    ? latestRows.join("")
    : `<div class="empty">No daily records yet.</div>`;

  $("#totalsTitle").textContent = isAdmin ? "All-time totals" : "Operations totals";
  const totalRows = [
    row("Bags produced", num(s.total_produced)),
    row("Bags sold", num(s.total_sold)),
    row("Inventory", num(s.inventory)),
    row("Unpaid bagger dues", money(s.unpaid_baggers, c)),
  ];
  if (isAdmin) {
    totalRows.length = 0;
    totalRows.push(
      row("Sales revenue", money(s.total_sales, c)),
      row("Bagger payments", money(s.total_bagger, c)),
      row("Fuel expenses", money(s.total_fuel, c)),
      row("Occasional expenses", money(s.total_occasional, c)),
      row("Raw materials", money(s.total_materials, c)),
      row("Debt outstanding", money(s.total_debt, c)),
      row("Sir Rich inflow", money(s.sir_rich, c)),
      row("Cash in hand", money(s.cash_in_hand, c), true, s.cash_in_hand < 0)
    );
  }
  $("#allTimeStats").innerHTML = totalRows.join("");

  $("#dashDailyBody").innerHTML =
    state.daily
      .slice(0, 10)
      .map((r) => {
        const cashCell = isAdmin
          ? `<td class="num ${moneyClass(r.calculated_cash)}">${money(r.calculated_cash, c)}</td>`
          : "";
        return `<tr>
      <td>${r.date || "—"}</td>
      <td class="num">${num(r.produced)}</td>
      <td class="num">${num((r.sold_out || 0) + (r.sold_inside || 0))}</td>
      ${isAdmin ? `<td class="num">${money(r.expected_out_cash, c)}</td>` : ""}
      ${isAdmin ? `<td class="num">${money(r.inside_cash, c)}</td>` : ""}
      ${cashCell}
    </tr>`;
      })
      .join("") || `<tr><td colspan="${isAdmin ? 6 : 5}" class="empty">No records</td></tr>`;

  renderDaily();
  renderBaggers();
  renderExpenses();
  renderMaterials();
  fillSettings();
  renderAccount();
}

function metric(label, value, cls) {
  return `<div class="metric"><div class="label">${label}</div><div class="value ${cls || ""}">${value}</div></div>`;
}

function row(k, v, emphasis = false, bad = false) {
  return `<div class="stat-row ${emphasis ? "emphasis" : ""} ${bad ? "bad" : ""}"><span class="k">${k}</span><span class="v">${v}</span></div>`;
}

function actions(collection, id) {
  const del = isAdmin
    ? `<button type="button" class="mini-btn danger" data-del="${collection}" data-id="${id}">Del</button>`
    : "";
  return `<td class="row-actions">
    <button type="button" class="mini-btn" data-edit="${collection}" data-id="${id}">Edit</button>
    ${del}
  </td>`;
}

function renderDaily() {
  const c = cur();
  $("#dailyBody").innerHTML =
    state.daily
      .map((r) => {
        const cash = isAdmin
          ? `<td class="num ${moneyClass(r.calculated_cash)}">${money(r.calculated_cash, c)}</td>`
          : "";
        const cashCols = isAdmin
          ? `<td class="num">${money(r.inside_cash, c)}</td>
      <td class="num">${money(r.expected_out_cash, c)}</td>`
          : `<td class="num">—</td><td class="num">—</td>`;
        return `<tr>
      <td>${esc(r.date || "—")}</td>
      <td class="num">${esc(String(r.week ?? "—"))}</td>
      <td class="num">${num(r.produced)}</td>
      <td class="num">${num(r.sold_out)}</td>
      <td class="num">${num(r.asanteman)}</td>
      <td class="num">${num(r.sold_inside)}</td>
      ${cashCols}
      <td class="num">${money(r.fuel, c)}</td>
      <td class="num">${money(r.new_debt, c)}</td>
      <td class="num">${money(r.debt_paid, c)}</td>
      ${cash}
      ${actions("daily", r.id)}
    </tr>`;
      })
      .join("") ||
    `<tr><td colspan="13" class="empty">No daily records yet. Add one to start.</td></tr>`;
}

function renderBaggers() {
  const c = cur();
  $("#baggersBody").innerHTML =
    state.baggers
      .map(
        (b) => `<tr>
      <td>${b.date || "—"}</td>
      <td>${esc(b.worker)}</td>
      <td class="num">${num(b.bags_done)}</td>
      <td class="num">${num(b.rate)}</td>
      <td class="num">${money(b.due, c)}</td>
      <td><span class="tag ${b.paid ? "yes" : "no"}">${b.paid ? "Yes" : "No"}</span></td>
      ${actions("baggers", b.id)}
    </tr>`
      )
      .join("") || `<tr><td colspan="7" class="empty">No bagger payments yet.</td></tr>`;
}

function renderExpenses() {
  const c = cur();
  $("#expensesBody").innerHTML =
    state.expenses
      .map(
        (e) => `<tr>
      <td>${e.date || "—"}</td>
      <td>${esc(e.description)}</td>
      <td class="num">${money(e.amount, c)}</td>
      <td>${esc(e.notes || "")}</td>
      ${actions("expenses", e.id)}
    </tr>`
      )
      .join("") || `<tr><td colspan="5" class="empty">No expenses yet.</td></tr>`;
}

function renderMaterials() {
  const c = cur();
  $("#materialsBody").innerHTML =
    state.materials
      .map(
        (m) => `<tr>
      <td>${m.date || "—"}</td>
      <td>${esc(m.item)}</td>
      <td class="num">${money(m.amount, c)}</td>
      <td>${esc(m.notes || "")}</td>
      ${actions("materials", m.id)}
    </tr>`
      )
      .join("") || `<tr><td colspan="5" class="empty">No raw materials yet.</td></tr>`;
}

function fillSettings() {
  const f = $("#settingsForm");
  if (!f || !state?.settings) return;
  f.business_name.value = state.settings.business_name || "";
  f.bag_price.value = state.settings.bag_price ?? 6.5;
  f.default_bagger_rate.value = state.settings.default_bagger_rate ?? 0.3;
  f.currency.value = state.settings.currency || "₵";
}

function renderAccount() {
  if (!currentUser) return;
  $("#accountInfo").innerHTML = [
    row("Name", esc(currentUser.display_name || "—")),
    row("Username", esc(currentUser.username || "—")),
    row("Role", isAdmin ? "Administrator" : "Worker"),
  ].join("");
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/* ── Users ───────────────────────────────────────────────── */

async function loadUsers() {
  if (!isAdmin) return;
  try {
    const data = await api("/api/users");
    usersList = data.users || [];
    renderUsers();
  } catch (err) {
    toast(err.message, "err");
  }
}

function renderUsers() {
  const body = $("#usersBody");
  if (!body) return;
  body.innerHTML =
    usersList
      .map(
        (u) => `<tr>
      <td>${esc(u.display_name)}</td>
      <td><code class="mono">${esc(u.username)}</code></td>
      <td><span class="tag ${u.role === "admin" ? "yes" : "no"}">${u.role}</span></td>
      <td><span class="tag ${u.active ? "yes" : "no"}">${u.active ? "Active" : "Off"}</span></td>
      <td class="row-actions">
        <button type="button" class="mini-btn" data-edit-user="${u.id}">Edit</button>
        <button type="button" class="mini-btn danger" data-del-user="${u.id}">Del</button>
      </td>
    </tr>`
      )
      .join("") || `<tr><td colspan="5" class="empty">No users</td></tr>`;
}

/* ── Modal ───────────────────────────────────────────────── */

function openModal(collection, item = null) {
  const def = FORMS[collection];
  if (!def) return;
  modalCtx = { collection, id: item?.id || null, mode: collection === "users" ? "users" : "data" };
  $("#modalTitle").textContent = item ? def.titleEdit : def.titleAdd;
  const form = $("#modalForm");

  form.innerHTML = def.fields
    .map((f) => {
      if (f.adminOnly && !isAdmin) return "";
      // Non-admins cannot mark paid or set custom rates (server enforces too).
      if (!isAdmin && collection === "baggers" && (f.name === "paid" || f.name === "rate")) {
        return "";
      }
      let val = item ? item[f.name] : "";
      if (!item && f.name === "rate") val = state.settings.default_bagger_rate;
      if (!item && f.name === "active") val = true;
      if (!item && f.name === "role") val = "driver";
      if (item && f.name === "password") val = "";
      if (item && f.name === "password") {
        return `<label class="field"><span>New password (leave blank to keep)</span>
          <input name="password" type="password" minlength="6" autocomplete="new-password" /></label>`;
      }
      if (item && f.name === "username" && collection === "users") {
        return `<label class="field"><span>Username</span>
          <input name="username" type="text" value="${esc(val)}" disabled /></label>`;
      }
      if (f.type === "checkbox") {
        const checked = item ? !!item[f.name] : f.name === "active";
        return `<label class="check-row"><input type="checkbox" name="${f.name}" ${checked ? "checked" : ""} /> <span>${f.label}</span></label>`;
      }
      if (f.type === "select") {
        const opts = (f.options || [])
          .map((o) => `<option value="${esc(o.value)}" ${val === o.value ? "selected" : ""}>${esc(o.label)}</option>`)
          .join("");
        return `<label class="field"><span>${esc(f.label)}</span><select name="${esc(f.name)}" ${f.required ? "required" : ""}>${opts}</select></label>`;
      }
      if (f.type === "textarea") {
        return `<label class="field"><span>${esc(f.label)}</span><textarea name="${esc(f.name)}" ${f.required ? "required" : ""}>${esc(val ?? "")}</textarea></label>`;
      }
      const req = f.required && !(collection === "users" && f.name === "password" && item) ? "required" : "";
      // Always escape attribute values — blocks stored XSS in edit forms (e.g. materials.item).
      return `<label class="field"><span>${esc(f.label)}</span>
        <input name="${esc(f.name)}" type="${esc(f.type)}" ${f.step ? `step="${esc(f.step)}"` : ""}
          ${req} ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""}
          value="${esc(val ?? "")}" /></label>`;
    })
    .join("");

  $("#modal").hidden = false;
  form.querySelector("input,textarea,select")?.focus();
}

function closeModal() {
  $("#modal").hidden = true;
  modalCtx = { collection: null, id: null, mode: null };
}

async function saveModal(e) {
  e.preventDefault();
  const { collection, id, mode } = modalCtx;
  if (!collection) return;
  const form = $("#modalForm");
  const fd = new FormData(form);
  const body = {};

  for (const f of FORMS[collection].fields) {
    if (f.adminOnly && !isAdmin) continue;
    if (f.type === "checkbox") {
      body[f.name] = form.querySelector(`[name="${f.name}"]`)?.checked || false;
    } else if (form.querySelector(`[name="${f.name}"]`)) {
      const v = fd.get(f.name);
      body[f.name] = v === "" ? null : v;
    }
  }

  try {
    if (mode === "users") {
      if (id) {
        const payload = {
          display_name: body.display_name,
          role: body.role,
          active: body.active,
        };
        if (body.password) payload.password = body.password;
        const data = await api(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(payload) });
        usersList = data.users;
      } else {
        if (!body.password) throw new Error("Password is required");
        const data = await api("/api/users", { method: "POST", body: JSON.stringify(body) });
        usersList = data.users;
      }
      renderUsers();
      toast("User saved");
    } else {
      const payload = id ? { ...body, id } : body;
      if (id) {
        state = await api(`/api/${collection}/${id}`, { method: "PUT", body: JSON.stringify(payload) });
        toast("Updated");
      } else {
        state = await api(`/api/${collection}`, { method: "POST", body: JSON.stringify(payload) });
        toast("Added");
      }
      isAdmin = !!state.is_admin;
      currentUser = state.user || currentUser;
      renderAll();
    }
    closeModal();
  } catch (err) {
    toast(err.message, "err");
  }
}

async function deleteItem(collection, id) {
  if (!isAdmin) {
    toast("Only admin can delete", "err");
    return;
  }
  if (!id || id === "undefined" || id === "null") {
    console.error("deleteItem invalid id", collection, id);
    toast("Cannot delete: invalid record id", "err");
    return;
  }
  if (!confirm("Delete this record?")) return;
  try {
    console.log("deleteItem", collection, id);
    state = await api(`/api/${collection}/${id}`, { method: "DELETE" });
    console.log("deleteItem success", state);
    toast("Deleted");
    renderAll();
  } catch (err) {
    console.error("deleteItem failed", err);
    toast(err.message, "err");
  }
}

async function deleteUser(id) {
  if (!confirm("Delete this user account?")) return;
  try {
    const data = await api(`/api/users/${id}`, { method: "DELETE" });
    usersList = data.users;
    renderUsers();
    toast("User deleted");
  } catch (err) {
    toast(err.message, "err");
  }
}

/* ── Weekly / import / export ────────────────────────────── */

async function lookupWeek() {
  const w = Number($("#weekInput").value);
  if (!w) {
    toast("Enter a week number", "err");
    return;
  }
  try {
    const data = await api(`/api/weekly/${w}`);
    const c = cur();
    $("#weeklyStats").innerHTML = [
      row("Week", data.week),
      row("Bags sold (out)", num(data.bags_sold)),
      row("Production", num(data.production)),
      row("Revenue", money(data.revenue, c)),
      row("Fuel", money(data.fuel, c)),
      row("Bagger pay", money(data.bagger, c)),
      row("Occasional exp.", money(data.occasional, c)),
      row("Raw materials", money(data.materials, c)),
      row("Cost per bag", money(data.cost_per_bag, c), true),
    ].join("");
  } catch (err) {
    toast(err.message, "err");
  }
}

async function exportData() {
  try {
    const raw = await api("/api/export");
    const blob = new Blob([JSON.stringify(raw, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `tq-balance-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Exported");
  } catch (err) {
    toast(err.message, "err");
  }
}

async function importData(file) {
  try {
    const text = await file.text();
    const json = JSON.parse(text);
    state = await api("/api/import", { method: "POST", body: JSON.stringify(json) });
    renderAll();
    toast("Imported");
  } catch (err) {
    toast("Import failed: " + err.message, "err");
  }
}

/* ── Init ────────────────────────────────────────────────── */

function bind() {
  $$(".nav-btn").forEach((b) => b.addEventListener("click", () => setTab(b.dataset.tab)));
  $("#menuBtn")?.addEventListener("click", () => $(".sidebar").classList.toggle("open"));

  document.addEventListener("click", (e) => {
    const open = e.target.closest("[data-open]");
    if (open) openModal(open.dataset.open);

    const edit = e.target.closest("[data-edit]");
    if (edit) {
      const coll = edit.dataset.edit;
      const item = state[coll]?.find((x) => x.id === edit.dataset.id);
      if (item) openModal(coll, item);
    }

    const del = e.target.closest("[data-del]");
    if (del) deleteItem(del.dataset.del, del.dataset.id);

    const editUser = e.target.closest("[data-edit-user]");
    if (editUser) {
      const u = usersList.find((x) => x.id === editUser.dataset.editUser);
      if (u) openModal("users", u);
    }

    const delUser = e.target.closest("[data-del-user]");
    if (delUser) deleteUser(delUser.dataset.delUser);
  });

  $("#addUserBtn")?.addEventListener("click", () => openModal("users"));

  $("#modalClose").addEventListener("click", closeModal);
  $("#modalCancel").addEventListener("click", closeModal);
  $("#modal").addEventListener("click", (e) => {
    if (e.target === $("#modal")) closeModal();
  });
  $("#modalForm").addEventListener("submit", saveModal);

  $("#weekGo")?.addEventListener("click", lookupWeek);
  $("#weekInput")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") lookupWeek();
  });

  $("#exportBtn")?.addEventListener("click", exportData);
  $("#importFile")?.addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (f) importData(f);
    e.target.value = "";
  });

  $("#settingsForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      state = await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({
          business_name: f.business_name.value,
          bag_price: Number(f.bag_price.value),
          default_bagger_rate: Number(f.default_bagger_rate.value),
          currency: f.currency.value,
        }),
      });
      renderAll();
      toast("Settings saved");
    } catch (err) {
      toast(err.message, "err");
    }
  });

  $("#passwordForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.new_password.value !== f.confirm_password.value) {
      toast("Passwords do not match", "err");
      return;
    }
    try {
      await api("/api/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: f.current_password.value,
          new_password: f.new_password.value,
        }),
      });
      f.reset();
      toast("Password updated");
    } catch (err) {
      toast(err.message, "err");
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("#modal").hidden) closeModal();
  });
}

applyRoleUI();
bind();
refresh().catch((err) => {
  if (err.message !== "Login required") toast("Failed to load: " + err.message, "err");
});
