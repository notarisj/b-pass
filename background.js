// Use chrome.storage.session so the key survives service worker restarts
// (chrome.storage.session is cleared when the browser closes, not when the SW dies)

async function setSession(key, timeoutMinutes) {
  const expiry = timeoutMinutes > 0 ? Date.now() + timeoutMinutes * 60 * 1000 : 0;
  await chrome.storage.session.set({ sessionKey: key, sessionExpiry: expiry });
}

async function getSession() {
  const { sessionKey, sessionExpiry } = await chrome.storage.session.get(['sessionKey', 'sessionExpiry']);
  if (!sessionKey) return null;
  if (sessionExpiry > 0 && Date.now() > sessionExpiry) {
    await chrome.storage.session.remove(['sessionKey', 'sessionExpiry']);
    return null;
  }
  return sessionKey;
}

async function clearSession() {
  await chrome.storage.session.remove(['sessionKey', 'sessionExpiry']);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'SET_SESSION_KEY') {
    setSession(msg.key, msg.timeoutMinutes ?? 0).then(() => sendResponse({ success: true }));
    return true;
  }

  if (msg.action === 'GET_SESSION_KEY') {
    getSession().then(key => sendResponse({ key }));
    return true;
  }

  if (msg.action === 'CLEAR_SESSION') {
    clearSession().then(() => sendResponse({ success: true }));
    return true;
  }

  if (msg.action === 'FILL_ACTIVE_TAB') {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs[0]) { sendResponse({ success: false }); return; }
      chrome.tabs.sendMessage(tabs[0].id, {
        action: 'FILL_LOGIN',
        username: msg.username,
        password: msg.password,
        autoSubmit: msg.autoSubmit ?? false
      }, res => sendResponse(res || { success: false, error: 'No response from content script' }));
    });
    return true;
  }

  if (msg.action === 'OPEN_AND_FILL') {
    chrome.tabs.create({ url: msg.url }, tab => {
      const tabId = tab.id;
      const listener = (id, info) => {
        if (id !== tabId || info.status !== 'complete') return;
        chrome.tabs.onUpdated.removeListener(listener);
        setTimeout(() => {
          chrome.tabs.sendMessage(tabId, {
            action: 'FILL_LOGIN',
            username: msg.username,
            password: msg.password
          });
        }, 500);
      };
      chrome.tabs.onUpdated.addListener(listener);
    });
    sendResponse({ success: true });
    return true;
  }

  if (msg.action === 'LOGIN_FORM_DETECTED') {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0] && sender.tab && tabs[0].id === sender.tab.id) {
        chrome.action.setBadgeText({ text: '✓', tabId: sender.tab.id });
        chrome.action.setBadgeBackgroundColor({ color: '#4CAF50', tabId: sender.tab.id });
      }
    });
  }

  return true;
});

chrome.tabs.onActivated.addListener(info => {
  chrome.action.setBadgeText({ text: '', tabId: info.tabId });
});
