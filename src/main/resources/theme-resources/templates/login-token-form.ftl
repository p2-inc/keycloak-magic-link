<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("doLogIn")}
    <#elseif section = "form">
      <form id="kc-login-token-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        <div class="${properties.kcFormGroupClass!}">
          <div class="${properties.kcLabelWrapperClass!}">
            <label for="login_token" class="${properties.kcLabelClass!}">${msg("loginTokenLabel")}</label>
          </div>
          <div class="${properties.kcInputWrapperClass!}">
            <input id="login_token" name="login_token" type="text"
                   class="${properties.kcInputClass!}"
                   autocomplete="off" autofocus
                   aria-invalid="<#if message?has_content && message.type = 'error'>true</#if>"/>
          </div>
        </div>

        <#if message?has_content && message.type = 'error'>
          <div class="${properties.kcFormGroupClass!}">
            <span class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
              ${kcSanitize(message.summary)?no_esc}
            </span>
          </div>
        </#if>

        <div class="${properties.kcFormGroupClass!}">
          <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                   name="submit" id="kc-submit" type="submit" value="${msg("doSubmit")}"/>
          </div>
        </div>
      </form>
    </#if>
</@layout.registrationLayout>
