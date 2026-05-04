package io.phasetwo.keycloak.magic.auth.magic.spi;

import com.google.auto.service.AutoService;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * Keycloak SPI definition for magic link customization.
 *
 * <p>Discovered automatically via {@code @AutoService(Spi.class)}. Third parties can register
 * additional {@link MagicLinkCustomizationProvider} implementations by providing a
 * {@link MagicLinkCustomizationProviderFactory} annotated with
 * {@code @AutoService(ProviderFactory.class)}.
 */
@AutoService(Spi.class)
public final class MagicLinkCustomizationSpi implements Spi {

  public static final String SPI_NAME = "magic-link-customization";

  @Override
  public String getName() {
    return SPI_NAME;
  }

  @Override
  public Class<MagicLinkCustomizationProvider> getProviderClass() {
    return MagicLinkCustomizationProvider.class;
  }

  @Override
  @SuppressWarnings("rawtypes")
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return MagicLinkCustomizationProviderFactory.class;
  }

  @Override
  public boolean isInternal() {
    return false;
  }
}
