package io.phasetwo.keycloak.magic.auth;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import jakarta.ws.rs.core.MultivaluedMap;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.OptionalInt;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.get;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;

@JBossLog
public class MagicLinkAuthenticator implements Authenticator {

  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";
  static final String UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY = "ext-magic-update-password-action";

  static final String ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY = "ext-magic-allow-token-reuse";
  static final String ACTION_TOKEN_LIFE_SPAN = "ext-magic-token-life-span";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.authenticate");
    try {
      log.debug(context.getUser().getId() + " :" + context.getUser().getEmail());
      log.debug("module: " + context.getAuthenticationSession().getAuthNote("module"));
      log.debug("level:" + context.getAuthenticationSession().getAuthNote("level"));
      log.debug("org_id:" + context.getAuthenticationSession().getAuthNote("org_id"));
      log.debug("extra_permissions:" + context.getAuthenticationSession().getAuthNote("extra_permissions"));
    } catch (Exception e) {
      log.debug("No user found");
    }
    String attemptedUsername = MagicLink.getAttemptedUsername(context);
    log.debug("AttemptedUsername: " + attemptedUsername);


    context.success();

//    if (attemptedUsername == null) {
//      context.success();
//    } else {
//      log.debugf("Found attempted username %s from previous authenticator, skipping login form", attemptedUsername);
//      action(context);
//    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.action");
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = MagicLink.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    if (email == null) {
      email = MagicLink.getAttemptedUsername(context);
    }

    log.debugf("email in action is %s", email);
//    if (email == null) {
//      context.getEvent().error(Errors.USER_NOT_FOUND);
//      Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
//      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
//      return;
//    }

    String clientId = context.getSession().getContext().getClient().getClientId();
    UserModel user = MagicLink.getOrCreate(
        context.getSession(),
        context.getRealm(),
        email,
        isForceCreate(context, false),
        isUpdateProfile(context, false),
        isUpdatePassword(context, false),
        MagicLink.registerEvent(context.newEvent(), MAGIC_LINK)
    );

    // check for no/invalid email address
    if (user == null || MagicLink.trimToNull(user.getEmail()) == null || !MagicLink.isValidEmail(user.getEmail())) {
      log.debugf("user attempted to login with username/email: %s", email);
      context.getEvent()
          .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_EMAIL);
      context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    log.debugf("user is %s %s", user.getEmail(), user.isEnabled());
//    if (!enabledUser(context, user)) {
//      return; // the enabledUser method sets the challenge
//    }

    OptionalInt lifespan = getActionTokenLifeSpan(context, "");
    MagicLinkActionToken token = MagicLink.createActionToken(
        user,
        clientId,
        lifespan,
        rememberMe(context),
        context.getAuthenticationSession(),
        isActionTokenPersistent(context, true)
    );
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  private boolean rememberMe(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String rememberMe = formData.getFirst("rememberMe");
    return context.getRealm().isRememberMe()
        && rememberMe != null
        && rememberMe.equalsIgnoreCase("on");
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdateProfile(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdatePassword(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isActionTokenPersistent(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY, defaultValue);
  }

  private OptionalInt getActionTokenLifeSpan(AuthenticationFlowContext context, String defaultValue) {
    String lifespan = get(context, ACTION_TOKEN_LIFE_SPAN, defaultValue);
    if ("".equals(lifespan)) return OptionalInt.empty();

    try {
      return OptionalInt.of(Integer.parseInt(lifespan));
    } catch (NumberFormatException e) {
      log.error("Failed to parse lifespan", e);
      return OptionalInt.empty();
    }
  }

  @Override
  public void close() {

  }
}
