<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("magicLinkContinuationBodyHtml", realmName, magicLink))?no_esc}
</@layout.emailLayout>
