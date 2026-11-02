import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:8080/',

    env: {
      mailhogUrl: process.env.MAILHOG_URL || 'undefined',
      generatedMagicLink: process.env.GENERATED_MAGIC_LINK || 'undefined',
      generatedMagicLinkV2: process.env.GENERATED_MAGIC_LINK_V2 || 'undefined',
      invalidLoginHintLink: process.env.INVALID_LOGIN_HINT_LINK || 'undefined',
      linkUserA: process.env.LINK_USER_A || 'undefined',
      linkUserBAuto: process.env.LINK_USER_B_AUTO || 'undefined',
      linkUserBConfirm: process.env.LINK_USER_B_CONFIRM || 'undefined',
      linkUserBCancel: process.env.LINK_USER_B_CANCEL || 'undefined',
    },

    reporter: 'cypress-multi-reporters',

    reporterOptions: {
      configFile: 'reporter-config.json'
    },

    setupNodeEvents(on) {
      on('task', {

        log(message) {
          console.log(message);
          return null;
        },

        async redeemContinuationToken({
          baseUrl,
          token,
          clientId
        }: {
          baseUrl: string;
          token: string;
          clientId?: string;
        }) {

          const url = new URL(
            'realms/test-realm/login-actions/action-token',
            baseUrl
          );

          url.searchParams.set('key', token);

          if (clientId) {
            url.searchParams.set('client_id', clientId);
          }

          // Independent HTTP request, without browser cookies.
          // Abort after 15 seconds to prevent indefinite hangs.
          const response = await fetch(url, {
            redirect: 'manual',
            signal: AbortSignal.timeout(15000)
          });

          // Never return or log the authentication token.
          return {
            status: response.status
          };
        }

      });
    }
  }
});
