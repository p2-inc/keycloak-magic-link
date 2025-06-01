<#import "template.ftl" as layout>
<@layout.emailLayout>
<p>
  We detected a login attempt from <b>${ip}</b>
  (${city}, ${country}) using
  <b>${ua}</b> at <b>${time}</b>.
</p>
<p>
  Click the button <u>in the same browser window where you started login</u>.
</p>
${kcSanitize(msg("magicLinkBodyHtml", realmName, magicLink))?no_esc}
</@layout.emailLayout>
