package io.phasetwo.keycloak.magic.auth;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.InOrder;

/**
 * Unit tests for the spent-token branch of {@link LoginTokenHelper#completeAuth}.
 *
 * <p>Redeeming a single-use login token a second time fails the flow. At that point the {@code
 * login_hint} client note still holds the raw {@code lt:<uuid>} token, and a username form rendered
 * later in the same authentication session prefills the username from that note. The branch must
 * therefore drop the hint before failing, as the not-found and success paths already do. The
 * integration realms end on Keycloak's error page in this situation, so the effect is asserted at
 * the helper level.
 */
class LoginTokenHelperTest {

  private static final String TOKEN_ID = "0f0d3e3e-9b5f-4f0e-9d8a-5f2b2b6d4c11";

  @Test
  void completeAuth_spentSingleUseToken_clearsLoginHintBeforeFailing() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    KeycloakSession session = mock(KeycloakSession.class);
    SingleUseObjectProvider singleUse = mock(SingleUseObjectProvider.class);
    AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    UserModel user = mock(UserModel.class);

    when(context.getSession()).thenReturn(session);
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);
    // An earlier redemption already reserved this token.
    when(singleUse.putIfAbsent(anyString(), anyLong())).thenReturn(false);

    LoginTokenHelper.completeAuth(context, TOKEN_ID, Map.of(), null, user);

    InOrder inOrder = inOrder(authSession, context);
    inOrder.verify(authSession).removeClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
    inOrder
        .verify(authSession)
        .removeAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
    inOrder.verify(context).failure(AuthenticationFlowError.INVALID_CREDENTIALS);
    verify(context, never()).setUser(user);
    verify(context, never()).success();
  }
}
