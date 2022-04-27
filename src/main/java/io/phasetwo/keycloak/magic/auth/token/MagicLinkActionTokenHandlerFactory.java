package io.phasetwo.keycloak.magic.auth.token;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(ActionTokenHandlerFactory.class)
public class MagicLinkActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<MagicLinkActionToken> {

  public static final String PROVIDER_ID = "ext-magic-link";

  @Override
  public void close() {}

  @Override
  public MagicLinkActionTokenHandler create(KeycloakSession session) {
    return new MagicLinkActionTokenHandler();
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
