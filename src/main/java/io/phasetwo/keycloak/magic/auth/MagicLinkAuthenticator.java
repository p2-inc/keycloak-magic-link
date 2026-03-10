package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.get;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.OptionalInt;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

@JBossLog
public class MagicLinkAuthenticator extends UsernamePasswordForm {

  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";
  static final String UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY = "ext-magic-update-password-action";

  static final String ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY = "ext-magic-allow-token-reuse";
  static final String ACTION_TOKEN_LIFE_SPAN = "ext-magic-token-life-span";

  // Organization domain gating config properties
  static final String REQUIRE_ORGANIZATION_DOMAIN_CONFIG_PROPERTY =
      "ext-magic-require-organization-domain";
  static final String AUTO_ASSIGN_TO_ORGANIZATION_CONFIG_PROPERTY =
      "ext-magic-auto-assign-to-organization";
  static final String UNKNOWN_DOMAIN_REDIRECT_ERROR_CONFIG_PROPERTY =
      "ext-magic-unknown-domain-redirect-error";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.authenticate");
    String attemptedUsername = MagicLink.getAttemptedUsername(context);
    if (attemptedUsername == null) {
      super.authenticate(context);
    } else {
      log.debugf(
          "Found attempted username %s from previous authenticator, skipping login form",
          attemptedUsername);
      action(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String email = MagicLink.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    // check for empty email
    if (email == null) {
      // - first check for email from previous authenticator
      email = MagicLink.getAttemptedUsername(context);
    }
    log.debugf("email in action is %s", email);
    // - throw error if still empty
    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    // Organization domain gating check
    OrganizationModel matchedOrg = null;
    if (isRequireOrganizationDomain(context, false)) {
      String domain = extractDomainFromEmail(email);
      log.debugf("Organization domain gating enabled, checking domain: %s", domain);

      if (domain != null) {
        matchedOrg = findOrganizationByDomain(context, domain);
      }

      if (matchedOrg == null) {
        log.debugf("No organization found for domain: %s, redirecting with error", domain);
        redirectWithUnknownDomainError(context, email);
        return;
      }
      log.debugf("Found matching organization: %s for domain: %s", matchedOrg.getName(), domain);
    }

    String clientId = context.getSession().getContext().getClient().getClientId();

    EventBuilder event = context.newEvent();

    // Check if user exists before getOrCreate so we know if it's a new user
    UserModel existingUser =
        org.keycloak.models.utils.KeycloakModelUtils.findUserByNameOrEmail(
            context.getSession(), context.getRealm(), email);
    boolean isNewUser = existingUser == null;

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context, false),
            isUpdateProfile(context, false),
            isUpdatePassword(context, false),
            MagicLink.registerEvent(event, MAGIC_LINK));

    // check for no/invalid email address
    if (user == null
        || MagicLink.trimToNull(user.getEmail()) == null
        || !MagicLink.isValidEmail(user.getEmail())) {
      context
          .getEvent()
          .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_EMAIL);
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      log.debugf("user attempted to login with username/email: %s", email);
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    // Auto-assign newly created user to matched organization
    if (isNewUser && matchedOrg != null && isAutoAssignToOrganization(context, true)) {
      log.debugf(
          "Auto-assigning new user %s to organization %s", user.getEmail(), matchedOrg.getName());
      assignUserToOrganization(context, user, matchedOrg);
    }

    log.debugf("user is %s %s", user.getEmail(), user.isEnabled());

    // check for enabled user
    if (!enabledUser(context, user)) {
      return; // the enabledUser method sets the challenge
    }

    OptionalInt lifespan = getActionTokenLifeSpan(context, "");

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            clientId,
            lifespan,
            rememberMe(context),
            context.getAuthenticationSession(),
            isActionTokenPersistent(context, true));
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    context.challenge(context.form().createForm("view-email.ftl"));
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

  private OptionalInt getActionTokenLifeSpan(
      AuthenticationFlowContext context, String defaultValue) {
    String lifespan = get(context, ACTION_TOKEN_LIFE_SPAN, defaultValue);

    if ("".equals(lifespan)) {
      return OptionalInt.empty();
    }

    try {
      return OptionalInt.of(Integer.parseInt(lifespan));
    } catch (NumberFormatException e) {
      log.error("Failed to parse lifespan", e);
      return OptionalInt.empty();
    }
  }

  // Organization domain gating config helpers
  private boolean isRequireOrganizationDomain(
      AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, REQUIRE_ORGANIZATION_DOMAIN_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isAutoAssignToOrganization(
      AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, AUTO_ASSIGN_TO_ORGANIZATION_CONFIG_PROPERTY, defaultValue);
  }

  private String getUnknownDomainRedirectError(
      AuthenticationFlowContext context, String defaultValue) {
    return get(context, UNKNOWN_DOMAIN_REDIRECT_ERROR_CONFIG_PROPERTY, defaultValue);
  }

  /**
   * Extracts the domain portion from an email address.
   *
   * @param email the email address
   * @return the domain portion, or null if invalid
   */
  private String extractDomainFromEmail(String email) {
    if (email == null || !email.contains("@")) {
      return null;
    }
    int atIndex = email.lastIndexOf('@');
    if (atIndex < 0 || atIndex >= email.length() - 1) {
      return null;
    }
    return email.substring(atIndex + 1).toLowerCase();
  }

  /**
   * Finds an organization by email domain using Keycloak's OrganizationProvider.
   *
   * @param context the authentication flow context
   * @param domain the email domain to search for
   * @return the matching organization, or null if not found
   */
  private OrganizationModel findOrganizationByDomain(
      AuthenticationFlowContext context, String domain) {
    OrganizationProvider orgProvider = context.getSession().getProvider(OrganizationProvider.class);
    if (orgProvider == null) {
      log.warn("OrganizationProvider not available - organizations feature may not be enabled");
      return null;
    }

    // Use getByDomainName which handles domain lookup
    return orgProvider.getByDomainName(domain);
  }

  /**
   * Redirects to the client with an error for unknown domain.
   *
   * @param context the authentication flow context
   * @param email the email that was attempted
   */
  private void redirectWithUnknownDomainError(AuthenticationFlowContext context, String email) {
    String redirectUri = context.getAuthenticationSession().getRedirectUri();
    String state = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
    String errorCode = getUnknownDomainRedirectError(context, "unknown_domain");

    // Log the event
    context
        .getEvent()
        .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
        .detail("error", errorCode)
        .error("unknown_organization_domain");

    if (redirectUri != null) {
      // Build redirect URI with error parameters (OAuth 2.0 error response format)
      UriBuilder uriBuilder =
          UriBuilder.fromUri(URI.create(redirectUri))
              .queryParam("error", errorCode)
              .queryParam(
                  "error_description",
                  "Email domain is not associated with any organization");

      if (state != null) {
        uriBuilder.queryParam("state", state);
      }

      URI errorRedirectUri = uriBuilder.build();
      log.debugf("Redirecting to client with error: %s", errorRedirectUri);

      Response response = Response.status(Response.Status.FOUND)
          .location(errorRedirectUri)
          .build();
      context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
    } else {
      // Fallback: show form with error if no redirect URI
      log.warn("No redirect_uri available for unknown domain error redirect");
      context.failure(
          AuthenticationFlowError.ACCESS_DENIED,
          context
              .form()
              .setError("unknownOrganizationDomain")
              .createErrorPage(Response.Status.FORBIDDEN));
    }
  }

  /**
   * Assigns a user to an organization as a member.
   *
   * @param context the authentication flow context
   * @param user the user to assign
   * @param organization the target organization
   */
  private void assignUserToOrganization(
      AuthenticationFlowContext context, UserModel user, OrganizationModel organization) {
    OrganizationProvider orgProvider = context.getSession().getProvider(OrganizationProvider.class);
    if (orgProvider == null) {
      log.warn("OrganizationProvider not available - cannot assign user to organization");
      return;
    }

    try {
      // Add user as a member of the organization via the provider
      boolean added = orgProvider.addMember(organization, user);
      if (added) {
        log.infof(
            "Successfully assigned user %s to organization %s",
            user.getEmail(), organization.getName());
      } else {
        log.debugf(
            "User %s was already a member of organization %s",
            user.getEmail(), organization.getName());
      }
    } catch (Exception e) {
      log.errorf(
          e,
          "Failed to assign user %s to organization %s",
          user.getEmail(),
          organization.getName());
    }
  }

  @Override
  protected boolean validateForm(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("validateForm");
    return validateUser(context, formData);
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("challenge");
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) forms.setFormData(formData);
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    log.debug("createLoginForm");
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    log.debug("getDefaultChallengeMessage");
    return context.getRealm().isLoginWithEmailAllowed()
        ? Messages.INVALID_USERNAME_OR_EMAIL
        : Messages.INVALID_USERNAME;
  }
}
