const adminInput = document.querySelector("#admin-key");
const adminPanel = document.querySelector("#admin-key-panel");
const cardsNode = document.querySelector("#cards");
const notice = document.querySelector("#notice");
const keyDialog = document.querySelector("#key-dialog");
const loginDialog = document.querySelector("#login-dialog");
const newKey = document.querySelector("#new-key");
let knownCards = [];
let adminAuthorized = document.querySelector('meta[name="admin-authorized"]').content === "true";
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

const headers = () => ({"Content-Type": "application/json", "X-CSRF-Token": csrfToken});

function message(text, error = false) {
  notice.textContent = text;
  notice.className = `notice${error ? " error" : ""}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {...headers(), ...(options.headers || {})}});
  const data = await response.json().catch(() => ({error: `Server returned ${response.status} instead of JSON. Restart Flask and try again.`}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function escapeHtml(value) {
  const node = document.createElement("span");
  node.textContent = value;
  return node.innerHTML;
}

async function loadCards() {
  try {
    const {cards} = await api("/admin/cards");
    knownCards = cards;
    cardsNode.innerHTML = cards.length ? cards.map(card => {
      const balances = Object.entries(card.balances).filter(([, amount]) => Number(amount) !== 0);
      const balanceHtml = balances.length
        ? balances.map(([currency, amount]) => `<span>${escapeHtml(currency)} ${escapeHtml(amount)}</span>`).join("")
        : '<span class="empty">No available balance</span>';
      return `
      <article class="bank-card ${card.status}">
        <header><h3>${escapeHtml(card.label)}</h3><span>${escapeHtml(card.status)}</span></header>
        <div class="card-number">${escapeHtml(card.card_number)}</div>
        <div class="balance">${balanceHtml}</div>
        <footer><span>${escapeHtml(card.holder)} · ${card.login_configured ? "Login ready" : "No login"}</span>
          <span class="card-actions">
            <button data-action="login" data-number="${card.card_number.replace(/\s/g, "")}">${card.login_configured ? "Reset login" : "Set login"}</button>
            <button data-action="key" data-number="${card.card_number.replace(/\s/g, "")}">New API key</button>
            <button data-action="status" data-number="${card.card_number.replace(/\s/g, "")}" data-status="${card.status === "active" ? "frozen" : "active"}">${card.status === "active" ? "Freeze" : "Unfreeze"}</button>
            <button class="danger-button" data-action="delete" data-number="${card.card_number.replace(/\s/g, "")}" data-label="${escapeHtml(card.label)}">Delete</button>
          </span>
        </footer>
      </article>`;
    }).join("") : '<p class="muted">No cards yet.</p>';
    message("Connected securely.");
  } catch (error) { message(error.message, true); }
}

function showKey(key) { newKey.textContent = key; keyDialog.showModal(); }

document.querySelector("#connect").addEventListener("click", async () => {
  try {
    await api("/api/admin/unlock", {method: "POST", body: JSON.stringify({admin_key: adminInput.value})});
    adminInput.value = "";
    adminAuthorized = true;
    adminPanel.classList.add("hidden");
    await loadCards();
    message("Management unlocked for seven days on this browser.");
  } catch (error) { message(error.message, true); }
});
document.querySelector("#refresh").addEventListener("click", loadCards);
document.querySelector("#create-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const matchingCard = knownCards.find(card => card.holder.trim().toLocaleLowerCase() === data.holder.trim().toLocaleLowerCase());
    if (matchingCard && confirm(`${matchingCard.holder} already has ${matchingCard.label} (${matchingCard.card_number}). Is this the same person?\n\nChoose OK to link both cards, or Cancel to keep them as separate people.`)) data.linked_card_number = matchingCard.card_number;
    const result = await api("/admin/cards", {method: "POST", body: JSON.stringify(data)});
    showKey(result.api_key);
    event.currentTarget.reset();
    if (window.detectedBankCurrency) document.querySelector("#new-card-currency").value = window.detectedBankCurrency;
    await loadCards();
  } catch (error) { message(error.message, true); }
});

cardsNode.addEventListener("click", async event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  try {
    if (button.dataset.action === "login") {
      document.querySelector("#login-card-number").value = button.dataset.number;
      document.querySelector("#login-password").value = "";
      loginDialog.showModal();
    } else if (button.dataset.action === "key") {
      if (!confirm("Replace this card's API key? The old key will stop working.")) return;
      showKey((await api(`/admin/cards/${button.dataset.number}/replace-key`, {method: "POST", body: "{}"})).api_key);
    } else if (button.dataset.action === "delete") {
      if (!confirm(`Permanently delete ${button.dataset.label}? The balance must be zero and this cannot be undone.`)) return;
      await api(`/admin/cards/${button.dataset.number}`, {method: "DELETE"});
      await loadCards();
    } else {
      await api(`/admin/cards/${button.dataset.number}/status`, {method: "PATCH", body: JSON.stringify({status: button.dataset.status})});
      await loadCards();
    }
  } catch (error) { message(error.message, true); }
});

document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const cardNumber = document.querySelector("#login-card-number").value;
    const password = document.querySelector("#login-password").value;
    await api(`/admin/cards/${cardNumber}/login`, {method: "PUT", body: JSON.stringify({password})});
    loginDialog.close();
    await loadCards();
    message("Card login saved. The user can now log in with the displayed card number.");
  } catch (error) { message(error.message, true); }
});

document.querySelector("#copy-key").addEventListener("click", () => navigator.clipboard.writeText(newKey.textContent));
document.querySelector("#close-dialog").addEventListener("click", () => { newKey.textContent = ""; keyDialog.close(); });
document.querySelector("#close-login-dialog").addEventListener("click", () => loginDialog.close());

if (adminAuthorized) loadCards();
