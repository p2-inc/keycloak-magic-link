<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
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
  <form id="kc-form-login" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
    <div class="form-group">
      <div class="${properties.kcInputWrapperClass!}">
        <div class="g-recaptcha" data-callback="recaptcha_callback" data-size="compact" data-sitekey="${recaptchaSiteKey}"></div>
      </div>
    </div>
    <div class="${properties.kcFormGroupClass!}">
      <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
        <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
        <input tabindex="4" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}" disabled="disabled"/>
      </div>
    </div>
  </form>
  <script type="text/javascript">
    function recaptcha_callback(){
      document.getElementById("kc-login").disabled = false;
      document.getElementById("kc-form-login").submit();
    }
  </script>
  </#if>
</@layout.registrationLayout>
    
