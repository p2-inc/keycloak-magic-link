package io.phasetwo.keycloak.magic.resources;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.magic.TinyUrlCleanupHelper;
import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.timer.TimerProvider;
import org.keycloak.timer.TimerProviderFactory;

@AutoService(RealmResourceProviderFactory.class)
public class TinyUrlResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "login";

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    return new TinyUrlResourceProvider(keycloakSession);
  }

  @Override
  public void init(Scope scope) {}

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    KeycloakSession keycloakSession = keycloakSessionFactory.create();
    TimerProviderFactory timerProviderFactory =
        (TimerProviderFactory) keycloakSessionFactory.getProviderFactory(TimerProvider.class);

    timerProviderFactory
        .create(keycloakSession)
        .scheduleTask(
            TinyUrlCleanupHelper::cleanupOldUrlkeys,
            TinyUrlConstants.TINY_URL_CLEANUP_INTERVAL,
            "tiny-url-cleaner");
  }

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
