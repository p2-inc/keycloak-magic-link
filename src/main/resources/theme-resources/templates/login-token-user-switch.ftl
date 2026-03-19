<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("doLogIn")}
    <#elseif section = "form">
      <form id="kc-user-switch-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        <div class="${properties.kcFormGroupClass!}">
          <p>${msg("magicLinkUserSwitchInfoPre")}<strong>${currentUsername}</strong>${msg("magicLinkUserSwitchInfoPost")}</p>
        </div>

        <div class="${properties.kcFormGroupClass!}">
          <div id="kc-form-buttons" style="display:flex; gap:1rem;">
            <button class="${properties.kcButtonClass!} pf-m-secondary ${properties.kcButtonLargeClass!}"
                    name="action" id="kc-cancel" type="submit" value="cancel" style="flex:1;">
              ${msg("doCancel")}
            </button>
            <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                    name="action" id="kc-logout" type="submit" value="logout" style="flex:1;">
              ${msg("magicLinkLogoutAndContinue")}
            </button>
          </div>
        </div>
      </form>
    </#if>
</@layout.registrationLayout>
