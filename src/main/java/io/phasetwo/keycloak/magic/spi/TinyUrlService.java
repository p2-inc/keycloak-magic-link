package io.phasetwo.keycloak.magic.spi;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import java.util.Optional;
import org.keycloak.provider.Provider;

public interface TinyUrlService extends Provider {
  Optional<TinyUrl> findByUrlKey( String urlKey);
}
