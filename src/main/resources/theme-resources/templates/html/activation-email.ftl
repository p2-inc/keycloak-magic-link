<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("activationEmailBodyHtml", realmName, activationLink, linkExpirationMinutes))?no_esc}
</@layout.emailLayout>
