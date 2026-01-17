<#import "template.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=false; section>
 <#if section = "header">
    <div id="kc-username" class="${properties.kcFormGroupClass!}">
      <label id="kc-attempted-username">${auth.attemptedUsername}</label>
      <a id="reset-login" href="${url.loginRestartFlowUrl}" aria-label="${msg("restartLoginTooltip")}">
        <div class="kc-login-tooltip">
          <i class="${properties.kcResetFlowIcon!}"></i>
          <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
        </div>
      </a>
    </div>
  <#elseif section = "form">
    <div id="mlc-status">${msg("magicLinkContinuationWaiting")!msg("magicLinkContinuationConfirmation")}</div>
    <div id="mlc-exp"></div>
    <script>
      (function(){
        const pollingUrl = "${pollingUrl!""}";
        const loginActionUrl = "${url.loginAction?no_esc}";
        const statusEl = document.getElementById("mlc-status");
        const expEl = document.getElementById("mlc-exp");
        let stopped = false;

        async function tick(){
          if(stopped) return;
          try{
            const r = await fetch(pollingUrl, {
              cache: "no-store",
              credentials: "same-origin"
            });
            
            if(!r.ok){
              if(r.status === 404 || r.status === 401){
                stopped = true;
                statusEl.textContent = "${msg("magicLinkContinuationExpired")!"Your link has expired. Please request a new one."}";
                expEl.textContent = "";
                return;
              }
              throw new Error("status:" + r.status);
            }
            
            const data = await r.json();

            if(typeof data.expires_in === "number"){
              expEl.textContent = data.expires_in > 0
                ? "${msg("magicLinkContinuationExpiresIn")!"Expires in"} " + data.expires_in + "s"
                : "";
            }

            switch(data.state){
              case "confirmed":
                stopped = true;
                statusEl.textContent = "${msg("magicLinkContinuationRedirecting")!"Redirecting..."}";
                window.location.href = loginActionUrl;
                return;
              case "expired":
                stopped = true;
                statusEl.textContent = "${msg("magicLinkContinuationExpired")!"Your link has expired. Please request a new one."}";
                expEl.textContent = "";
                return;
              default: // pending
                setTimeout(tick, 2500);
            }
          } catch(e){
            // Network error or server unavailable - retry with backoff
            setTimeout(tick, 4000);
          }
        }
        tick();
      })();
  </script>
  </#if>
</@layout.registrationLayout>
