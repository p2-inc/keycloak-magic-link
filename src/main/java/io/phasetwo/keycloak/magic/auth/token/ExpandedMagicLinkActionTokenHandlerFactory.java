package io.phasetwo.keycloak.magic.auth.token;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(ActionTokenHandlerFactory.class)
public class ExpandedMagicLinkActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<ExpandedMagicLinkActionToken> {

  public static final String PROVIDER_ID = "exp-magic-link";

  @Override
  public void close() {}

  @Override
  public ExpandedMagicLinkActionTokenHandler create(KeycloakSession session) {
    return new ExpandedMagicLinkActionTokenHandler();
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
