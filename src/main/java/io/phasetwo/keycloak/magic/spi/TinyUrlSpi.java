package io.phasetwo.keycloak.magic.spi;

import com.google.auto.service.AutoService;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

@AutoService(Spi.class)
public class TinyUrlSpi implements Spi {
  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return "tinyurl-spi";
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return TinyUrlService.class;
  }

  @Override
  @SuppressWarnings("rawtypes")
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return TinyUrlServiceProviderFactory.class;
  }
}
