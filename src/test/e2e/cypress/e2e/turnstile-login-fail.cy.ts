/**
 * Turnstile Username+Password — CAPTCHA fails scenario.
 *
 * WireMock is configured by Java to return { success:false } for the
 * Cloudflare siteverify endpoint before this spec runs.
 *
 * When credentials are correct but Turnstile fails, Keycloak adds the VERIFY_EMAIL
 * required action and redirects the browser to the email-verification step.
 */

const realmBase = `${Cypress.config('baseUrl')}realms/turnstile-realm`;
const loginUrl =
  `${realmBase}/protocol/openid-connect/auth` +
  `?response_type=code&client_id=account&scope=openid` +
  `&redirect_uri=${encodeURIComponent(`${realmBase}/account`)}`;

describe('Turnstile Username Password — CAPTCHA fails', () => {

  it('redirects to email verification when CAPTCHA fails despite correct credentials', () => {
    cy.visit(loginUrl);
    cy.get('#username').type('test@phasetwo.io');
    cy.get('#password').type('test123');
    cy.get('#kc-login').click();

    // Keycloak adds VERIFY_EMAIL and redirects to the required-action step
      cy.url().should('contain', '/turnstile-realm/');
      cy.url().should('contain', 'login-actions');

      cy.should('not.contain', 'Personal');
  });
});