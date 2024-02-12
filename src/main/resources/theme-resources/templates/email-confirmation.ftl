<#import "template.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=false; section>
  <#if section = "form">
    ${msg("magicLinkSuccesfullLogin")}
  </#if>
</@layout.registrationLayout>
