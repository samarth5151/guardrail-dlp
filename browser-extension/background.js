// Background service worker — handles icon badge updates
chrome.runtime.onInstalled.addListener(() => {
  console.log('[DLP Guardian] Extension installed and active.');
});
