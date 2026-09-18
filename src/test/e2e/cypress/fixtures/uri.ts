const testRealmUri = Cypress.config('baseUrl') + "realms/test-realm";
const testRealmAuthUri = testRealmUri.concat("/protocol/openid-connect/auth");
const testRealmLoginUri = testRealmAuthUri.concat(
    '?response_type=code',
    '&client_id=account',
    '&scope=openid',
    '&redirect_uri=', testRealmUri.concat("/account")
);

const emailOtpRealmUri = Cypress.config('baseUrl') + "realms/email-otp-realm";
const emailOtpRealmAuthUri = emailOtpRealmUri.concat("/protocol/openid-connect/auth");
const emailOtpRealmLoginUri = emailOtpRealmAuthUri.concat(
    '?response_type=code',
    '&client_id=account',
    '&scope=openid',
    '&redirect_uri=', emailOtpRealmUri.concat("/account")
);

const emailOtpBruteForceRealmUri = Cypress.config('baseUrl') + "realms/email-otp-brute-force-realm";
const emailOtpBruteForceRealmAuthUri = emailOtpBruteForceRealmUri.concat("/protocol/openid-connect/auth");
const emailOtpBruteForceRealmLoginUri = emailOtpBruteForceRealmAuthUri.concat(
    '?response_type=code',
    '&client_id=account',
    '&scope=openid',
    '&redirect_uri=', emailOtpBruteForceRealmUri.concat("/account")
);

const mailhogBaseUrl = Cypress.env('mailhogUrl')

export {
    testRealmLoginUri,
    testRealmUri,
    emailOtpRealmLoginUri,
    emailOtpRealmUri,
    emailOtpBruteForceRealmLoginUri,
    emailOtpBruteForceRealmUri,
    mailhogBaseUrl,
}
