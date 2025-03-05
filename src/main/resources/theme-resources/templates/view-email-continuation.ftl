<#import "template.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=false; section>
 <#if section = "header">
    <div id="kc-username" class="${properties.kcFormGroupClass!}">
      <label id="kc-attempted-username">${auth.attemptedUsername}</label>
      <a id="reset-login" href="${url.loginRestartFlowUrl}" aria-label="${msg("restartLoginTooltip")}">
        <div class="kc-login-tooltip">
          <i class="${properties.kcResetFlowIcon!}"></i>
          <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
        </div>
      </a>
    </div>
  <#elseif section = "form">
    ${msg("magicLinkContinuationConfirmation")}
  </#if>
  <script>
     (function (w, d) {
             function checkAuthStatus() {
                 fetch(w.location + "/magic-link/magic-link-continuation/verify", {
                     method: 'GET',
                     headers: {
                         'X-Requested-With': 'XMLHttpRequest',
                         'Pragma': 'no-cache',
                         'Cache-Control': 'no-cache, no-store'
                     },
                     cache: 'no-store',
                     body:  {"sessionId" : ${AUTH_SESSION_ID}}
                 })
                 .then(response => {
                    if(response == true){

                    }
                 })
                 .catch(error => {
                     console.error('[Magic Link Debug] Error checking auth status:', error);
                     setTimeout(checkAuthStatus, 5000);
                 });
             }

             // Start polling after a delay
             setTimeout(checkAuthStatus, 5000);
          })(window, document);
  </script>
</@layout.registrationLayout>
