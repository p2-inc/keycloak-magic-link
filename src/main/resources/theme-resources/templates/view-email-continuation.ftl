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
    <script>
       (function (w, d) {
          setTimeout(function(){
             w.location.reload(1);
          }, 5000);
       })(window, document);
    </script>
  </#if>
</@layout.registrationLayout>
