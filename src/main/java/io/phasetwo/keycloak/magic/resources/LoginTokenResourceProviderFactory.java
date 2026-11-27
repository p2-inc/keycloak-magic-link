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
   * SPI option that selects the format of newly issued tokens. Defaults to {@code true} (legacy
   * format). {@code --spi-realm-restapi-extension--login-token--legacy=false} switches to
   * stateless tokens; set it only after every node runs a version that can verify them.
   *
   * <p>The format is a server-side decision: callers of the endpoint cannot choose it. It only
   * affects issuing — tokens of either format are always accepted on redemption.
   */
  static final String CONFIG_LEGACY = "legacy";

  private boolean legacyFormat = true;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public LoginTokenResourceProvider create(KeycloakSession session) {
    return new LoginTokenResourceProvider(session, legacyFormat);
  }

  @Override
  public void init(Config.Scope config) {
    legacyFormat = config.getBoolean(CONFIG_LEGACY, true);
    log.infof("[LT] issuing login tokens in the %s format", legacyFormat ? "legacy" : "stateless");
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
