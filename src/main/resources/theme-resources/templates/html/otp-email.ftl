<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("otpBodyHtml", loginSubjectName, code))?no_esc}
</@layout.emailLayout>
