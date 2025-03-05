package io.phasetwo.keycloak.magic.auth;

import static io.phasetwo.keycloak.magic.MagicLink.CREATE_NONEXISTENT_USER_CONFIG_PROPERTY;
import static io.phasetwo.keycloak.magic.MagicLink.MAGIC_LINK;
import static io.phasetwo.keycloak.magic.auth.util.Authenticators.is;
import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.SESSION_CONFIRMED;
import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.SESSION_EXPIRATION;
import static io.phasetwo.keycloak.magic.auth.util.MagicLinkConstants.TIMEOUT;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkContinuationActionToken;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.utils.StringUtil;

@JBossLog
public class MagicLinkContinuationAuthenticator extends UsernamePasswordForm {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        log.debug("MagicLinkContinuationAuthenticator.authenticate");

        String attemptedUsername = MagicLink.getAttemptedUsername(context);
        if (attemptedUsername == null) {
            super.authenticate(context);
        } else {
            var parentSessionId = context.getAuthenticationSession().getParentSession().getId();

            context.challenge(
                    context.form()
                            .setAttribute("authSessionId", parentSessionId)
                            .setAttribute("realmUri", context.getUriInfo().getBaseUri() + "realms/" + context.getRealm().getName())
                            .createForm("view-email-continuation.ftl")
            );
        }
    }

    private boolean sessionExpired(AuthenticationFlowContext context) {
        String expiration = context.getAuthenticationSession().getAuthNote(SESSION_EXPIRATION);
        if (StringUtil.isNotBlank(expiration)) {
            ZonedDateTime expirationTime = ZonedDateTime.parse(expiration);
            return expirationTime.isBefore(ZonedDateTime.now());
        }
        return false;
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

        if (sessionExpired(context)) {
            AuthenticationSessionManager manager = new AuthenticationSessionManager(context.getSession());
            manager.removeTabIdInAuthenticationSession(
                    context.getRealm(), context.getAuthenticationSession());

            context.getEvent().error(Errors.SESSION_EXPIRED);
            Response challengeResponse =
                    challenge(context, Messages.EXPIRED_ACTION_TOKEN_NO_SESSION, FIELD_USERNAME);
            context.failureChallenge(
                    AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse);
            return;
        }

        var parentSessionId = context.getAuthenticationSession().getParentSession().getId();
        SingleUseObjectProvider singleUseStore = context.getSession().singleUseObjects();
        Map<String, String> session = singleUseStore.get(parentSessionId);

        if (isSessionConfirmed(session)) {
            authenticateUser(context, email);
        } else {
            // To inform "expired_token" to the client, the lifespan of the cache provider is longer than device code
            int timeout = getTimeout(context, 10);

            int validityInSecs = 60 * timeout;

            Map<String, String> sessionConfirmedMap = new HashMap<>();
            sessionConfirmedMap.put(SESSION_CONFIRMED, "false");
            singleUseStore.put(parentSessionId, validityInSecs, sessionConfirmedMap);

            String clientId = context.getSession().getContext().getClient().getClientId();

            EventBuilder event = context.newEvent();

            UserModel user =
                    MagicLink.getOrCreate(
                            context.getSession(),
                            context.getRealm(),
                            email,
                            isForceCreate(context, false),
                            false,
                            false,
                            MagicLink.registerEvent(event, MAGIC_LINK));

            // check for no/invalid email address
            if (user == null
                    || MagicLink.trimToNull(user.getEmail()) == null
                    || !MagicLink.isValidEmail(user.getEmail())) {
                context.getEvent()
                        .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
                        .event(EventType.LOGIN_ERROR).error(Errors.INVALID_EMAIL);
                context
                        .getAuthenticationSession()
                        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
                log.debugf("user attempted to login with username/email: %s", email);
                context.forceChallenge(context.form().createForm("view-email.ftl"));
                return;
            }

            log.debugf("user is %s %s", user.getEmail(), user.isEnabled());

            // check for enabled user
            if (!enabledUser(context, user)) {
                return; // the enabledUser method sets the challenge
            }

            MagicLinkContinuationActionToken token =
                    MagicLink.createExpandedActionToken(
                            user, clientId, validityInSecs, context.getAuthenticationSession());
            String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
            boolean sent = MagicLink.sendMagicLinkContinuationEmail(context.getSession(), user, link);
            log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

            context
                    .getAuthenticationSession()
                    .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);

            String sessionExpiration =
                    ZonedDateTime.now()
                            .plusMinutes(timeout)
                            .plusSeconds(2) // clock skew
                            .toString();
            context.getAuthenticationSession().setAuthNote(SESSION_EXPIRATION, sessionExpiration);

            context.challenge(context.form()
                    .setAttribute("authSessionId", parentSessionId)
                    .setAttribute("realmUri", context.getUriInfo().getBaseUri() + "realms/" + context.getRealm().getName())
                    .createForm("view-email-continuation.ftl")
            );
        }
    }

    private static void authenticateUser(AuthenticationFlowContext context, String email) {
        UserModel user;
        if (MagicLink.isValidEmail(email)) {
            user = context.getSession().users().getUserByEmail(context.getRealm(), email);
        } else {
            user =
                    context.getSession().users().getUserByUsername(context.getRealm(), email);
        }
        context.setUser(user);
        context.success();
    }

    private static boolean isSessionConfirmed(Map<String, String> session) {
        return Objects.nonNull(session) && StringUtil.isNotBlank(session.get(SESSION_CONFIRMED)) && Boolean.parseBoolean(session.get(SESSION_CONFIRMED));
    }

    private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
        return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
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

    private int getTimeout(AuthenticationFlowContext context, int defaultValue) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) return defaultValue;

        Map<String, String> config = authenticatorConfig.getConfig();
        if (config == null) return defaultValue;
        try {
            return Integer.parseInt(config.get(TIMEOUT));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
