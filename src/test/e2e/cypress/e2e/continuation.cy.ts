import {mailhogBaseUrl, testRealmLoginUri} from '../fixtures/uri';

describe('Magic link continuation waiting page', () => {
    for (const [email, expectedMessages] of [
        ['testuser@phasetwo.io', 1],
        ['nonexistent@phasetwo.io', 0],
    ] as const) {
        it(`shows the same pending UI for ${email}`, () => {
            cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');
            cy.intercept('GET', '**/magic-link-continuation/*/*/status').as('status');
            cy.visit(testRealmLoginUri);
            cy.get('#username').type(email);
            cy.get('#kc-login').click();

            checkWaitingPage();
            cy.wait('@status').then(({response}) => {
                expect(response.statusCode).to.equal(200);
                expect(response.body.state).to.equal('pending');
                expect(response.body.expires_in).to.be.within(1, 600);
            });
            cy.reload();
            checkWaitingPage();
            cy.wait('@status').then(({response}) => {
                expect(response.body.state).to.equal('pending');
                expect(response.body.expires_in).to.be.within(1, 600);
            });
            cy.request(mailhogBaseUrl + '/api/v2/messages').then(({body}) => {
                expect(body.total).to.equal(expectedMessages);
            });
        });
    }
});

function checkWaitingPage() {
    cy.get('#mlc-status').should('contain.text', 'Waiting for confirmation');
    cy.get('#kc-attempted-username').should('have.text', 'Sign in to your account');
    cy.get('#mlc-exp', {timeout: 15000}).should('contain.text', 'Expires in');
    cy.contains('Resend').should('not.exist');
    cy.get('body').should('not.contain.text', 'existing-user');
}
