package io.phasetwo.keycloak.magic.rest;

import com.google.auto.service.AutoService;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for MagicLinkContinuationStatusProvider
 *
 * <p>This provider exposes a public endpoint used during the authentication flow and does not
 * require user/admin authentication.
 */
@AutoService(RealmResourceProviderFactory.class)
public class MagicLinkContinuationStatusProviderFactory implements RealmResourceProviderFactory {
  // ID defines the base path: /realms/{realm}/magic-link-continuation
  public static final String ID = "magic-link-continuation";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new MagicLinkContinuationStatusProvider(session);
  }

  @Override
  public void init(org.keycloak.Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }
}

