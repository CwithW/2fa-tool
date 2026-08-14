import { generateTotp, parseToken } from "./totp.js";
import { buildTokenUrl, readTokensFromFragment } from "./url-state.js";

const HISTORY_BURST_MS = 700;
const TIMER_CIRCUMFERENCE = 2 * Math.PI * 18;

const input = document.querySelector("#token-input");
const tokenCount = document.querySelector("#token-count");
const clearButton = document.querySelector("#clear-button");
const codeList = document.querySelector("#code-list");
const cardTemplate = document.querySelector("#code-card-template");

let entries = [];
let historyBurstTimer;
let isHistoryBurstActive = false;
let renderVersion = 0;

function getInputTokens() {
  return input.value
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function readTokensFromUrl() {
  return readTokensFromFragment(window.location.hash);
}

function syncUrl(tokens) {
  const nextUrl = buildTokenUrl(window.location.href, tokens);
  const nextRelativeUrl = `${nextUrl.pathname}${nextUrl.search}${nextUrl.hash}`;
  const currentRelativeUrl = `${location.pathname}${location.search}${location.hash}`;

  if (nextRelativeUrl === currentRelativeUrl) {
    return;
  }

  if (isHistoryBurstActive) {
    history.replaceState(null, "", nextRelativeUrl);
  } else {
    history.pushState(null, "", nextRelativeUrl);
    isHistoryBurstActive = true;
  }

  clearTimeout(historyBurstTimer);
  historyBurstTimer = setTimeout(() => {
    isHistoryBurstActive = false;
  }, HISTORY_BURST_MS);
}

function showCardError(card, title, detail) {
  card.classList.add("invalid");
  card.setAttribute("aria-invalid", "true");

  const pin = card.querySelector(".pin");
  pin.textContent = title;
  pin.disabled = true;

  const status = card.querySelector(".copy-status");
  status.textContent = detail;
  status.classList.add("error");
  card.querySelector(".timer").hidden = true;
}

function createCard(entry) {
  const card = cardTemplate.content.firstElementChild.cloneNode(true);
  const label = card.querySelector(".card-label");
  const detail = card.querySelector(".card-detail");
  const pin = card.querySelector(".pin");

  label.textContent = entry.token?.label ?? `Token ${entry.index + 1} · Invalid`;
  detail.textContent = entry.token?.detail ?? "";
  detail.hidden = !detail.textContent;
  pin.addEventListener("click", () => copyCode(card, entry.code));

  if (entry.error) {
    showCardError(card, "Invalid token", entry.error.message);
  }

  return card;
}

async function copyCode(card, code) {
  if (!code) {
    return;
  }

  const status = card.querySelector(".copy-status");

  try {
    await navigator.clipboard.writeText(code);
    status.textContent = "Copied";
    status.classList.add("copied");
    setTimeout(() => {
      status.textContent = "Click the code to copy";
      status.classList.remove("copied");
    }, 1400);
  } catch {
    status.textContent = "Clipboard access was denied";
  }
}

function updateTimer(card, token, now) {
  const elapsed = (now / 1000) % token.period;
  const remaining = Math.ceil(token.period - elapsed);
  const fraction = remaining / token.period;
  const progress = card.querySelector(".timer-progress");

  card.querySelector(".seconds").textContent = remaining;
  progress.style.strokeDashoffset = String(TIMER_CIRCUMFERENCE * (1 - fraction));
}

async function updateCodes(now = Date.now()) {
  const version = renderVersion;

  await Promise.all(
    entries.map(async (entry, index) => {
      if (entry.error) {
        return;
      }

      const card = codeList.children[index];
      updateTimer(card, entry.token, now);

      const counter = Math.floor(now / 1000 / entry.token.period);
      if (entry.counter === counter) {
        return;
      }

      entry.counter = counter;
      try {
        const code = await generateTotp(entry.token, now);
        if (version !== renderVersion) {
          return;
        }
        entry.code = code;
        card.querySelector(".pin").textContent = code;
      } catch {
        if (version !== renderVersion) {
          return;
        }
        showCardError(card, "Code error", "This browser could not generate a TOTP code");
      }
    }),
  );
}

function render() {
  const tokens = getInputTokens();
  renderVersion += 1;

  entries = tokens.map((value, index) => {
    try {
      return { index, token: parseToken(value, index), counter: null, code: "" };
    } catch (error) {
      return { index, error, counter: null, code: "" };
    }
  });

  const errorCount = entries.filter((entry) => entry.error).length;
  const tokenLabel = `${tokens.length} ${tokens.length === 1 ? "token" : "tokens"}`;
  tokenCount.textContent = errorCount ? `${tokenLabel} · ${errorCount} invalid` : tokenLabel;
  tokenCount.classList.toggle("has-errors", errorCount > 0);
  input.setAttribute("aria-invalid", String(errorCount > 0));

  codeList.replaceChildren();

  if (entries.length === 0) {
    const emptyState = document.createElement("div");
    emptyState.className = "empty-state";
    emptyState.innerHTML =
      '<div class="empty-icon" aria-hidden="true">•••</div><p>Your 2FA codes will appear here.</p>';
    codeList.append(emptyState);
    return;
  }

  entries.forEach((entry) => codeList.append(createCard(entry)));
  void updateCodes();
}

function applyTokens(tokens) {
  input.value = tokens.join("\n");
  render();
}

input.addEventListener("input", () => {
  const tokens = getInputTokens();
  syncUrl(tokens);
  render();
});

clearButton.addEventListener("click", () => {
  input.value = "";
  syncUrl([]);
  render();
  input.focus();
});

window.addEventListener("popstate", () => {
  clearTimeout(historyBurstTimer);
  isHistoryBurstActive = false;
  applyTokens(readTokensFromUrl());
});

applyTokens(readTokensFromUrl());
setInterval(() => void updateCodes(), 200);
