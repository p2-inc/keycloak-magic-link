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
  it('sends the configured external continuation URL', () => {
    // Clear previous messages.
    cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

    // Start a new authentication attempt.
    cy.visit(testRealmLoginUri);

    cy.get('#username').type('testuser@phasetwo.io');
    cy.get('#kc-login').click();

    // The original session should be waiting.
    checkWaitingPage();

    // Retrieve the generated email.
    cy.request(mailhogBaseUrl + '/api/v2/messages')
      .then(({body}) => {
        expect(body.total).to.equal(1);

        const emailBody = String(body.items[0].Content.Body);

        // Check the external URL without exposing the token.
        expect(
          emailBody.includes(
            'https://capture.example.test/magic-login?key='
          )
        ).to.equal(true);
      });
  });
  it('redeems external continuation token without client_id', () => {
    let confirmed = false;

    // Remove messages from previous tests.
    cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

    // Monitor the original browser's polling endpoint.
    cy.intercept(
      'GET',
      '**/magic-link-continuation/*/*/status',
      (req) => {
        req.continue((res) => {
          if (res.body?.state === 'confirmed') {
            confirmed = true;
          }
        });
      }
    ).as('continuationStatus');

    // Start a new authentication session.
    cy.visit(testRealmLoginUri);

    cy.get('#username').type('testuser@phasetwo.io');
    cy.get('#kc-login').click();

    checkWaitingPage();

    // Verify initial state.
    cy.wait('@continuationStatus')
      .its('response.body.state')
      .should('eq', 'pending');

    // Retrieve the email containing the external URL.
    cy.request(mailhogBaseUrl + '/api/v2/messages')
      .then(({body}) => {
        expect(body.total).to.equal(1);

        const emailBody = String(body.items[0].Content.Body);

        // Extract the JWT without printing it.
        const match = emailBody.match(
          /https:\/\/capture\.example\.test\/magic-login\?key=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/
        );

        expect(match, 'signed external URL').not.to.be.null;

        const token = match![1];

        // Redeem directly against Keycloak without client_id.
        // This request does not share the waiting browser's cookies.
        cy.task(
          'redeemContinuationToken',
          {
            baseUrl: Cypress.config('baseUrl'),
            token: token
          },
          { log: false }
        ).then((result: any) => {
          expect(result.status).to.be.within(200, 399);
        });
      });

    // The original browser must receive confirmation.
    cy.wrap(null, {timeout: 20000}).should(() => {
      expect(
        confirmed,
        'waiting session received confirmed status'
      ).to.equal(true);
    });
  });
});

function checkWaitingPage() {
  cy.get('#mlc-status').should('contain.text', 'Waiting for confirmation');
  cy.get('#kc-attempted-username').should('have.text', 'Sign in to your account');
  cy.get('#mlc-exp', {timeout: 15000}).should('contain.text', 'Expires in');
  cy.contains('Resend').should('not.exist');
  cy.get('body').should('not.contain.text', 'existing-user');
}
