// Field detection heuristics
const USERNAME_SIGNALS = ['user', 'login', 'email', 'uname', 'userid', 'account', 'username', 'identifier', 'id', 'loginid'];
const PASSWORD_SIGNALS = ['pass', 'pwd', 'password', 'secret', 'credentials'];

function scoreField(el, signals) {
  let score = 0;
  const attrs = [el.name, el.id, el.placeholder, el.autocomplete, el.getAttribute('aria-label')];
  attrs.forEach(attr => {
    if (!attr) return;
    const val = attr.toLowerCase();
    signals.forEach(sig => { if (val.includes(sig)) score += 5; });
  });
  return score;
}

function findLoginForm() {
  const forms = document.querySelectorAll('form');
  let best = null;
  let bestScore = -1;

  const tryForm = (container) => {
    const pwFields = [...container.querySelectorAll('input[type="password"]')];
    if (pwFields.length !== 1) return;
    const pwField = pwFields[0];

    const textFields = [...container.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')];
    let userField = null;
    let userScore = -1;
    textFields.forEach(f => {
      const s = scoreField(f, USERNAME_SIGNALS) + (f.type === 'email' ? 10 : 0) +
        (f.autocomplete === 'username' || f.autocomplete === 'email' ? 10 : 0);
      if (s > userScore) { userScore = s; userField = f; }
    });

    if (!userField && textFields.length === 1) userField = textFields[0];
    if (!userField) {
      // fallback: field immediately before password in DOM order
      const allInputs = [...container.querySelectorAll('input')];
      const pwIdx = allInputs.indexOf(pwField);
      if (pwIdx > 0) userField = allInputs[pwIdx - 1];
    }

    const score = (userField ? 5 : 0) + scoreField(pwField, PASSWORD_SIGNALS);
    if (score > bestScore) {
      bestScore = score;
      best = { userField, pwField, form: container };
    }
  };

  forms.forEach(tryForm);
  if (!best) tryForm(document.body);
  return best;
}

function fillField(el, value) {
  if (!el) return;
  el.focus();
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  nativeInputValueSetter.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

const SUBMIT_BUTTON_SIGNALS = ['login', 'log in', 'sign in', 'signin', 'submit', 'continue', 'next', 'enter', 'go'];

function submitForm(form) {
  if (!form) return;

  // 1. Look for a submit button inside the form
  const candidates = [
    ...form.querySelectorAll('button[type="submit"]'),
    ...form.querySelectorAll('input[type="submit"]'),
    ...form.querySelectorAll('button:not([type="button"]):not([type="reset"])'),
  ];

  // Score by text content matching common login button labels
  let best = null, bestScore = -1;
  candidates.forEach(el => {
    const text = (el.textContent || el.value || el.getAttribute('aria-label') || '').toLowerCase().trim();
    const score = SUBMIT_BUTTON_SIGNALS.reduce((s, sig) => text.includes(sig) ? s + 5 : s, 0) + (el.type === 'submit' ? 3 : 0);
    if (score > bestScore) { bestScore = score; best = el; }
  });

  // Small delay so React/Vue state can sync after fill events
  setTimeout(() => {
    if (best) {
      best.click();
    } else {
      // Fallback: dispatch a submit event on the form
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    }
  }, 120);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'FILL_LOGIN') {
    const form = findLoginForm();
    if (!form) { sendResponse({ success: false, error: 'No login form found' }); return; }
    fillField(form.userField, msg.username);
    fillField(form.pwField, msg.password);
    if (msg.autoSubmit) submitForm(form.form || form.pwField.closest('form'));
    sendResponse({ success: true });
  }

  if (msg.action === 'DETECT_FORMS') {
    const login = findLoginForm();
    sendResponse({
      hasLoginForm: !!login,
      url: window.location.href
    });
  }

  if (msg.action === 'GET_FORM_HINTS') {
    const login = findLoginForm();
    const hints = {};
    if (login?.userField) {
      hints.usernameValue = login.userField.value;
    }
    sendResponse(hints);
  }
});

// Notify background when a page with a login form loads
(function notifyBackground() {
  const login = findLoginForm();
  if (login) {
    chrome.runtime.sendMessage({ action: 'LOGIN_FORM_DETECTED', url: window.location.href }).catch(() => {});
  }
})();
