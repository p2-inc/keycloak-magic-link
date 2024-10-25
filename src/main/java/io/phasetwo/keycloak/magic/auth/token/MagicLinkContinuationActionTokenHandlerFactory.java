package io.phasetwo.keycloak.magic.auth.token;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(ActionTokenHandlerFactory.class)
public class MagicLinkContinuationActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<MagicLinkContinuationActionToken> {

  public static final String PROVIDER_ID = "magic-link-continuation";

  @Override
  public void close() {}

  @Override
  public MagicLinkContinuationLinkActionTokenHandler create(KeycloakSession session) {
    return new MagicLinkContinuationLinkActionTokenHandler();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}
}
