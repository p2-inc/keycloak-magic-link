package io.phasetwo.keycloak.magic.auth.token;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(ActionTokenHandlerFactory.class)
public class BoundMagicLinkActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<BoundMagicLinkActionToken> {

  public static final String PROVIDER_ID = "ext-bound-magic-link";

  @Override
  public void close() {}

  @Override
  public BoundMagicLinkActionTokenHandler create(KeycloakSession session) {
    return new BoundMagicLinkActionTokenHandler();
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
