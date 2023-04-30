<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("otpBody", realmName, code))?no_esc}
</@layout.emailLayout>
