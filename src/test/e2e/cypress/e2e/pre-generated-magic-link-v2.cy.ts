describe('Magic Link v2 browser-flow authenticator', () => {
  it('Following a v2 link completes the browser flow and returns an authorization code', () => {
    const v2Link = Cypress.env('generatedMagicLinkV2');
    cy.task('log', 'The v2 link from the Java code is: ' + v2Link);
    cy.visit(v2Link, { failOnStatusCode: false });
    cy.url().should('include', 'code=');
  });
});
