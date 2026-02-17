import { defineConfig } from "cypress";

export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:8080/',
    env: {
      mailhogUrl: process.env.MAILHOG_URL || 'undefined'
    },
    reporter: 'cypress-multi-reporters',
    reporterOptions: {
      configFile: 'reporter-config.json'
    },
    setupNodeEvents(on) {
      on('task', {
        log(message) {
          console.log(message)
          return null
        },
      })
    },
  },
});
