const buttons = document.querySelectorAll(".side-button");
const panels = document.querySelectorAll(".panel");

function activatePanel(name) {
  buttons.forEach(b => b.classList.toggle("active", b.dataset.panel === name));
  panels.forEach(p => p.classList.toggle("active-panel", p.id === name));
  if (name === "bookmarks") loadBookmarks();
  if (name === "history") loadHistory();
}

buttons.forEach(button => {
  button.addEventListener("click", () => {
    history.replaceState(null, "", "#" + button.dataset.panel);
    activatePanel(button.dataset.panel);
  });
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[ch]);
}

function card(item, removable = false) {
  return `
    <div class="item-card">
      <div>
        <a href="${escapeHtml(item.url)}">${escapeHtml(item.title || item.url)}</a>
        <div class="item-url">${escapeHtml(item.url)}</div>
        <div class="item-time">${escapeHtml(item.created_at || item.visited_at || "")}</div>
      </div>
      ${removable ? `<button class="delete-button" data-id="${item.id}">Remove</button>` : ""}
    </div>`;
}

async function loadBookmarks() {
  const response = await fetch("/api/bookmarks");
  const items = await response.json();
  const list = document.getElementById("bookmark-list");
  list.innerHTML = items.length ? items.map(item => card(item, true)).join("") :
    `<div class="item-card"><div>No bookmarks yet. Open a page and press ☆ or Ctrl+D.</div></div>`;

  list.querySelectorAll(".delete-button").forEach(button => {
    button.addEventListener("click", async () => {
      await fetch(`/api/bookmarks/${button.dataset.id}`, {method: "DELETE"});
      loadBookmarks();
    });
  });
}

async function loadHistory() {
  const response = await fetch("/api/history");
  const items = await response.json();
  const list = document.getElementById("history-list");
  list.innerHTML = items.length ? items.map(item => card(item)).join("") :
    `<div class="item-card"><div>No local history yet.</div></div>`;
}

document.getElementById("clear-history").addEventListener("click", async () => {
  await fetch("/api/history", {method: "DELETE"});
  loadHistory();
});

const requested = location.hash.slice(1);
if (["home", "bookmarks", "history"].includes(requested)) {
  activatePanel(requested);
}
