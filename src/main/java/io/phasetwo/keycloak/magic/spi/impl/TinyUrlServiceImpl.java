package io.phasetwo.keycloak.magic.spi.impl;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import javax.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class TinyUrlServiceImpl implements TinyUrlService {

  private final KeycloakSession session;

  public TinyUrlServiceImpl(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Optional<TinyUrl> findByUrlKey(String urlKey) {
    List<TinyUrl> tinyUrls =
        getEntityManager()
            .createNamedQuery("findByUrlKey", TinyUrl.class)
            .setParameter("urlKey", urlKey)
            .setParameter("realmId", getRealm().getName())
            .getResultList();
    return Optional.ofNullable(tinyUrls.size() > 0 ? tinyUrls.get(0) : null);
  }

  @Override
  public List<TinyUrl> findAllKeysOlderThan(long time) {
    List<TinyUrl> tinyUrls =
        getEntityManager()
            .createNamedQuery("findAllKeysOlderThan", TinyUrl.class)
            .setParameter("time", Instant.ofEpochSecond(time))
            .getResultList();
    return tinyUrls;
  }

  @Override
  public TinyUrl addTinyUrl(TinyUrl tinyUrl) {
    getEntityManager().persist(tinyUrl);
    return tinyUrl;
  }

  @Override
  public void hardDeleteTinyUrl(TinyUrl tinyUrl) {
    getEntityManager().remove(tinyUrl);
  }

  @Override
  public void close() {}

  private RealmModel getRealm() {
    return session.getContext().getRealm();
  }

  private EntityManager getEntityManager() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }
}
