/**
 * Turnstile Username+Password — CAPTCHA passes scenario.
 *
 * WireMock is configured by Java to return { success:true, action:"login" } for the
 * Cloudflare siteverify endpoint before this spec runs.
 *
 * The login.ftl always renders a fallback hidden cf-turnstile-response input so the form
 * submits a token regardless of whether the Cloudflare CDN widget loads in headless mode.
 */

const realmBase = `${Cypress.config('baseUrl')}realms/turnstile-realm`;
const loginUrl =
  `${realmBase}/protocol/openid-connect/auth` +
  `?response_type=code&client_id=account&scope=openid` +
  `&redirect_uri=${encodeURIComponent(`${realmBase}/account`)}`;

describe('Turnstile Username Password — CAPTCHA passes', () => {

  it('shows the login form with the Turnstile widget placeholder', () => {
    cy.visit(loginUrl);
    cy.get('#username').should('be.visible');
    cy.get('#password').should('be.visible');
    cy.get('.cf-turnstile').should('exist');
  });

  it('logs in and redirects to account when CAPTCHA passes', () => {
    cy.visit(loginUrl);
    cy.get('#username').type('test@phasetwo.io');
    cy.get('#password').type('test123');
    cy.get('#kc-login').click();

    cy.url().should('contain', '/turnstile-realm/');
    cy.url().should('not.contain', 'login-actions');

    cy.contains('Personal')
  });
});
