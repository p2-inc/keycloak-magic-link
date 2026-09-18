import { mailhogBaseUrl, emailOtpRealmLoginUri } from "../fixtures/uri";
import { user1, } from "../fixtures/users";

describe('Basic tests with the Email OTP authenticator', () => {
    it('User who exists in the realm should be able to log in with the code emailed to them', () => {
        cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

        cy.visit(emailOtpRealmLoginUri);
        cy.get('#username').type(user1.username);
        cy.get('#kc-login').click();

        cy.contains('Enter access code');

        cy.wrap(null).then(() => {
            return fetchOtpEmail(user1.username)
        })
            .then((mail) => {
                const body = mail.Content.Body;
                expect(body).to.contain('Someone requested a one-time-password to login to Email OTP Realm');

                const code = extractOtpCode(body);
                cy.log(`OTP code: ${code}`);

                // Submitting a wrong code re-shows the form with an error, and the
                // real code still works afterwards.
                const wrongCode = code === '000000' ? '111111' : '000000';
                cy.get('#otp').type(wrongCode);
                cy.get('#kc-submit').click();
                cy.contains('Invalid access code');

                cy.get('#otp').clear().type(code);
                cy.get('#kc-submit').click();
            });

        cy.url().should('contain', 'email-otp-realm');
        cy.contains('Personal');
    });

    it('Non-existent user should be rejected at the username form and no email should be sent', () => {
        cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

        cy.visit(emailOtpRealmLoginUri);
        cy.get('#username').type('nonexistent@phasetwo.io');
        cy.get('#kc-login').click();

        cy.contains('Invalid username or email');

        cy.wait(5000);

        cy.request(mailhogBaseUrl + '/api/v2/messages').then((response) => {
            expect(response.body.total).to.equal(0);
            expect(response.body.items).to.have.length(0);
        });
    });
});

function fetchOtpEmail(toEmail) {
    return cy
        .request({
            method: 'GET',
            url: mailhogBaseUrl + '/api/v2/messages',
            retryOnStatusCodeFailure: true,
        })
        .then((res) => {
            const messages = res.body.items

            const mail = messages.find((msg) => {
                const to = msg.To.map((t) => t.Mailbox + '@' + t.Domain)
                const subject = msg.Content.Headers.Subject?.[0] || ''

                return (
                    to.includes(toEmail) &&
                    subject.includes('Your access code for')
                )
            })

            expect(mail, 'otp email').to.exist
            return mail
        })
}

function extractOtpCode(body) {
    const match = body.match(/Code:\s*(\d{6})/)
    expect(match, 'otp code').to.not.be.null
    return match[1]
}
