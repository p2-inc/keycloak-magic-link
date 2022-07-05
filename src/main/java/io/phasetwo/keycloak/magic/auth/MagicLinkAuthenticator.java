package io.phasetwo.keycloak.magic.auth.token;

import io.phasetwo.keycloak.magic.MagicLink;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.LoginFormsUtil;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

@JBossLog
public class MagicLinkAuthenticator extends UsernamePasswordForm implements Authenticator {

  static final String CREATE_NONEXISTENT_USER_CONFIG_PROPERTY = "ext-magic-create-nonexistent-user";
  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";

  @Override
  public void action(AuthenticationFlowContext context) {
    log.info("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = formData.getFirst("username");
    // need to error check for null
    if (email == null || "".equals(email)) {
      // todo
    }
    String clientId = context.getSession().getContext().getClient().getClientId();
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    log.debugf("Attempting MagicLinkAuthenticator for %s, %s, %s", email, clientId, redirectUri);

    EventBuilder event = context.newEvent();

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            email,
            isForceCreate(context, false),
            isUpdateProfile(context, false),
            MagicLink.registerEvent(event));
    // need to check for no email address
    if (user == null || user.getEmail() == null || "".equals(user.getEmail())) {
      // todo
    }

    MagicLinkActionToken token =
        MagicLink.createActionToken(user, clientId, redirectUri, OptionalInt.empty());
    String link = MagicLink.linkFromActionToken(context.getSession(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    context.setUser(user);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdateProfile(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean is(AuthenticationFlowContext context, String propName, boolean defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(propName);
    if (v == null || "".equals(v)) return defaultValue;

    return v.trim().toLowerCase().equals("true");
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (context.getUser() != null) {
      // We can skip the form when user is re-authenticating. Unless current user has some IDP set,
      // so he can re-authenticate with that IDP
      List<IdentityProviderModel> identityProviders =
          LoginFormsUtil.filterIdentityProviders(
              context.getRealm().getIdentityProvidersStream(), context.getSession(), context);
      if (identityProviders.isEmpty()) {
        context.success();
        return;
      }
    }
    super.authenticate(context);
  }

  @Override
  protected boolean validateForm(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    return validateUser(context, formData);
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) forms.setFormData(formData);
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    if (context.getRealm().isLoginWithEmailAllowed()) return Messages.INVALID_USERNAME_OR_EMAIL;
    return Messages.INVALID_USERNAME;
  }
}
