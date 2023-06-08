package io.phasetwo.keycloak.magic.spi;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import java.util.List;
import java.util.Optional;
import org.keycloak.provider.Provider;

public interface TinyUrlService extends Provider {
  Optional<TinyUrl> findByUrlKey(String urlKey);

  List<TinyUrl> findAllKeysOlderThan(long time);

  public TinyUrl addTinyUrl(TinyUrl tinyUrl);

  public void hardDeleteTinyUrl(TinyUrl tinyUrl);
}
