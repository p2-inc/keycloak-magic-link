// ***********************************************************
// This example support/e2e.ts is processed and
// loaded automatically before your test files.
//
// This is a great place to put global configuration and
// behavior that modifies Cypress.
//
// You can change the location of this file or turn off
// automatically serving support files with the
// 'supportFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/configuration
// ***********************************************************

// Import commands.js using ES2015 syntax:
import './commands'

// Alternatively you can use CommonJS syntax:
// require('./commands')

// The tests log in as the "account" client with the account console URL as redirect_uri,
// so they land on /realms/<realm>/account/?session_state=...&iss=...&code=... . The
// console app re-authenticates using its current URL as redirect_uri, and Keycloak 26.7+
// rejects redirect_uri values carrying OAuth response parameters ("Invalid parameter:
// redirect_uri"). Strip that foreign authorization response before the app boots so it
// re-authenticates from a clean URL via the SSO session. The console's own callbacks
// always carry a state parameter and are left untouched.
Cypress.on('window:before:load', (win) => {
  const url = new URL(win.location.href);
  if (/\/realms\/[^/]+\/account\/?$/.test(url.pathname)
      && url.searchParams.has('code') && !url.searchParams.has('state')) {
    ['code', 'session_state', 'iss'].forEach((param) => url.searchParams.delete(param));
    win.history.replaceState(null, '', url.toString());
  }
});
