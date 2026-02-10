import {mailhogBaseUrl, testRealmLoginUri} from "../fixtures/uri";
import { user1, } from "../fixtures/users";

describe('Basic tests with the Magic Link Provider', () => {
   it('User who exists in the realm should be able to log into the account console', () => {
      cy.visit(testRealmLoginUri);
      cy.get('#username').type(user1.username);
      cy.get('#kc-login').click();

      cy.contains('Check your email, and click on the link to log in!');

      cy.task('log', 'Mailhog base URL is: ' + mailhogBaseUrl);

      cy.wrap(null).then(() => {
         return fetchLoginEmail(user1.username)
      })
          .then((mail) => {
              const body =
                  mail.Content.Body ||
                  mail.Content.Headers['Content-Type']?.includes('text/html')
                      ? mail.Content.Body
                      : ''

              expect(body).to.contain('Someone requested a login link to Test Realm Display Name')
              expect(body).to.contain('Click to log in.')

             const loginLink = extractLoginLink(body)
             cy.log(`Login link: ${loginLink}`)
             cy.visit(loginLink)
          });
      cy.url().should('contain', 'test-realm')
      cy.contains('Personal')
   })

   it('Non-existent user should see the check your email message but no email should be sent', () => {
      // 1. delete everything from mailhog
      cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

      // 2. try to log in with non-existent email
      cy.visit(testRealmLoginUri);
      cy.get('#username').type('nonexistent@phasetwo.io');
      cy.get('#kc-login').click();

      // 3. verify "check your email" message is present
      cy.contains('Check your email, and click on the link to log in!');

      // 4. wait ~5 secs
      cy.wait(5000);

      // 5. verify no email arrived in mailhog
      cy.request(mailhogBaseUrl + '/api/v2/messages').then((response) => {
         expect(response.body.total).to.equal(0);
         expect(response.body.items).to.have.length(0);
      });
   });
});

function fetchLoginEmail(toEmail) {
   return cy
       .request({
          method: 'GET',
          url: mailhogBaseUrl + '/api/v2/messages',
          retryOnStatusCodeFailure: true,
       })
       .then((res) => {
          const messages = res.body.items

          // find the email sent to example@example.com with subject containing "Log in to"
          const mail = messages.find((msg) => {
             const to = msg.To.map((t) => t.Mailbox + '@' + t.Domain)
             const subject = msg.Content.Headers.Subject?.[0] || ''

             return (
                 to.includes(toEmail) &&
                 subject.includes('Log in to Test Realm Display Name')
             )
          })

          expect(mail, 'login email').to.exist
          return mail
       })
}

function extractLoginLink(body) {

   const linkRegex = /https?:\/\/[^\s"]+/g
   const links = body.match(linkRegex)

   expect(links, 'login links').to.not.be.empty
   return links[0]
}