<#import "template.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=false; section>
  <#if section = "form">
    ${msg("magicLinkSuccessfulLogin")}
  </#if>
  <#if section = "form" && magicLinkContinuation.sameBrowser>
    <p><a href="${magicLinkContinuation.url}" id="mode-barcode">${msg("loginPage")}</a></p>
  </#if>
</@layout.registrationLayout>
