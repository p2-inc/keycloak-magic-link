package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@JBossLog
@AutoService(RealmResourceProviderFactory.class)
public class LoginTokenResourceProviderFactory implements RealmResourceProviderFactory {

  private static final String ID = "login-token";

  /**
   * SPI option that makes stateless tokens the default for requests that do not set {@code
   * stateless} themselves: {@code --spi-realm-restapi-extension--login-token--stateless=true}.
   * Enable it only after every node runs a version that can verify stateless tokens.
   */
  static final String CONFIG_STATELESS = "stateless";

  private boolean statelessByDefault;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public LoginTokenResourceProvider create(KeycloakSession session) {
    return new LoginTokenResourceProvider(session, statelessByDefault);
  }

  @Override
  public void init(Config.Scope config) {
    statelessByDefault = config.getBoolean(CONFIG_STATELESS, false);
    log.infof("[LT] stateless login tokens by default: %s", statelessByDefault);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
