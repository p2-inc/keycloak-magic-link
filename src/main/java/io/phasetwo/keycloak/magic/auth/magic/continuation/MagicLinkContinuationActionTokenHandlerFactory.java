package io.phasetwo.keycloak.magic.auth.magic.continuation;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(ActionTokenHandlerFactory.class)
public final class MagicLinkContinuationActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<MagicLinkContinuationActionToken> {

  public static final String PROVIDER_ID = "magic-link-continuation";

  @Override
  public MagicLinkContinuationActionTokenHandler create(KeycloakSession session) {
    return new MagicLinkContinuationActionTokenHandler();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
