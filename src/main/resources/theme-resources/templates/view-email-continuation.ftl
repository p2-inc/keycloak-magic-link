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
    <div id="kc-form">
       <div id="kc-form-wrapper">
          <form id="kc-form-login" action="${url.loginAction}" method="post">
             <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                <input style="display: none;" id="kc-login" type="submit"/>
             </div>
          </form>
       </div>
    </div>
  </#if>
  <script>
     (function (w, d) {
            function pollAuthStatus() {
                    fetch(`${realmUri}/magic-link-public/magic-link-continuation/verify`, {
                        method: 'POST',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest',
                            'Pragma': 'no-cache',
                            'Cache-Control': 'no-cache, no-store',
                            'Content-Type': 'application/json'
                        },
                        cache: 'no-store',
                        body: JSON.stringify({ "sessionId": "${authSessionId}" })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data === true) {
                             console.log("Authentication verified successfully.");
                             const button = document.getElementById('kc-login');
                             button.click();
                        } else {
                            console.log("Authentication pending... Retrying in 5 seconds.");
                        }
                    })
                    .catch(error => {
                        console.error('[Magic Link Debug] Error checking auth status:', error);
                    });
            }

           // Start polling with an interval of 5 seconds (5000 milliseconds)
           const pollingInterval = setInterval(pollAuthStatus, 5000);
          })(window, document);
  </script>
</@layout.registrationLayout>
