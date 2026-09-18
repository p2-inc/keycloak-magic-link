import { mailhogBaseUrl, emailOtpBruteForceRealmLoginUri } from "../fixtures/uri";
import { user1 } from "../fixtures/users";

// The realm sets failureFactor=3, so three wrong codes must temporarily disable
// the account. Keycloak only counts a failure when the authenticator's factory
// reports a reference category in DefaultBruteForceProtector.ALLOWED_AUTHENTICATION_CATEGORIES;
// while EmailOtpAuthenticatorFactory returned "alternate-auth" every failure was
// silently discarded. The resulting counters are asserted from the Java test via
// the admin attack-detection endpoint.
describe('Email OTP failures are counted by brute force protection', () => {
    it('Three wrong codes lock the account, so even the valid code is refused', () => {
        cy.request('DELETE', mailhogBaseUrl + '/api/v1/messages');

        cy.visit(emailOtpBruteForceRealmLoginUri);
        cy.get('#username').type(user1.username);
        cy.get('#kc-reset-password-form [type="submit"]').click();

        cy.contains('Enter access code');

        cy.wrap(null).then(() => {
            return fetchOtpEmail(user1.username)
        })
            .then((mail) => {
                // Read the real code only so the wrong ones cannot collide with it.
                const code = extractOtpCode(mail.Content.Body);
                cy.log(`OTP code: ${code}`);

                wrongCodes(code).forEach((wrong) => {
                    cy.get('#otp').clear().type(wrong);
                    cy.get('#kc-submit').click();
                    cy.contains('Invalid access code');
                });

                // The account is temporarily disabled now. The code above is still
                // the live one -- sendOtp() does not re-send while the auth note is
                // set -- so it would log us in if the lockout were not enforced.
                cy.get('#otp').clear().type(code);
                cy.get('#kc-submit').click();

                cy.contains('Invalid access code');
                cy.contains('Enter access code');
                cy.contains('Personal').should('not.exist');
                cy.url().should('include', 'login-actions');
            });
    });
});

function wrongCodes(realCode) {
    return ['000000', '111111', '222222'].map((c) => (c === realCode ? '999999' : c));
}

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
