describe('Invalid login token', () => {
  it('shows the login form with an empty username and the invalid token message', () => {
    const link = Cypress.env('invalidLoginHintLink');
    cy.task('log', 'The invalid login hint link from the Java code is: ' + link);
    cy.visit(link, { failOnStatusCode: false });
    cy.get('input[name="username"]').should('have.value', '');
    cy.contains('Invalid or expired login token. Please try again.');
  });
});
