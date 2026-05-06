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
    <p>${msg("magicLinkConfirmation")}</p>
    <form action="${url.loginAction}" method="post">
      <div class="${properties.kcFormGroupClass!}">
        <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
          <button
            type="submit"
            class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
          >
            ${msg("doResend")}
          </button>
        </div>
      </div>
    </form>
  </#if>
</@layout.registrationLayout>
