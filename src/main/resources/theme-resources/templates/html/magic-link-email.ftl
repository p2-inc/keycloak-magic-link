<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("magicLinkBodyHtml", loginSubjectName, magicLink))?no_esc}
</@layout.emailLayout>
