<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("otpBodyHtml", realmName, code))?no_esc}
</@layout.emailLayout>
