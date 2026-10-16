const form = document.querySelector("#exchange-form");
const result = document.querySelector("#exchange-result");
const confirmButton = document.querySelector("#exchange-button");
const chipsNode = document.querySelector(".balance-chips");
const csrf = document.querySelector('meta[name="csrf-token"]').content;

function values() { return Object.fromEntries(new FormData(form)); }
function show(text, error = false) { result.textContent = text; result.className = `notice${error ? " error" : ""}`; }

function selectSource(chip) {
  const alreadySelected = chip.classList.contains("selected");
  form.elements.from_currency.value = chip.dataset.currency;
  if (alreadySelected) form.elements.amount.value = chip.dataset.amount;
  confirmButton.disabled = true;
  result.className = "notice hidden";
  document.querySelectorAll(".balance-chip").forEach(item => item.classList.toggle("selected", item === chip));
  form.elements.amount.focus();
}

function makeChip(currency, amount) {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.className = "balance-chip";
  chip.dataset.currency = currency;
  chip.dataset.amount = amount;
  chip.title = `Select ${currency}; click again to use the full balance`;
  const label = document.createElement("strong");
  label.textContent = currency;
  chip.append(label, ` ${amount}`);
  return chip;
}

function renderBalances(balances) {
  const available = Object.entries(balances).filter(([, amount]) => Number(amount) !== 0);
  chipsNode.replaceChildren();
  form.elements.from_currency.replaceChildren();
  if (!available.length) {
    const emptyChip = document.createElement("span");
    emptyChip.className = "empty-balance";
    emptyChip.textContent = "No available balance";
    chipsNode.append(emptyChip);
    const emptyOption = new Option("No available balance", "", true, true);
    emptyOption.disabled = true;
    form.elements.from_currency.add(emptyOption);
    return;
  }
  available.forEach(([currency, amount]) => {
    chipsNode.append(makeChip(currency, amount));
    form.elements.from_currency.add(new Option(currency, currency));
  });
}

async function quote() {
  const data = values();
  confirmButton.disabled = true;
  try {
    const response = await fetch(`/api/exchange/quote?from=${encodeURIComponent(data.from_currency)}&to=${encodeURIComponent(data.to_currency)}&amount=${encodeURIComponent(data.amount)}`);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error);
    show(`${body.quote.amount} ${body.quote.from_currency} ≈ ${body.quote.converted_amount} ${body.quote.to_currency} at ${body.quote.rate} (${body.quote.date || "latest"}).`);
    confirmButton.disabled = false;
  } catch (error) { show(error.message || "Could not retrieve a quote", true); }
}

chipsNode.addEventListener("click", event => {
  const chip = event.target.closest(".balance-chip");
  if (chip) selectSource(chip);
});
document.querySelector("#quote-button").addEventListener("click", quote);
form.addEventListener("input", () => { confirmButton.disabled = true; });
form.elements.from_currency.addEventListener("change", event => {
  document.querySelectorAll(".balance-chip").forEach(chip => chip.classList.toggle("selected", chip.dataset.currency === event.target.value));
});
form.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const response = await fetch("/api/exchange", {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(values())});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error);
    renderBalances(body.card.balances);
    form.elements.amount.value = "";
    show(`Exchanged ${body.quote.amount} ${body.quote.from_currency} into ${body.quote.converted_amount} ${body.quote.to_currency}. Balances updated.`);
    confirmButton.disabled = true;
  } catch (error) { show(error.message || "Exchange failed", true); }
});
