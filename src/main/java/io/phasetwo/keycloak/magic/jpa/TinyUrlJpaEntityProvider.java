package io.phasetwo.keycloak.magic.jpa;

import java.util.Collections;
import java.util.List;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

public class TinyUrlJpaEntityProvider implements JpaEntityProvider {

  @Override
  public List<Class<?>> getEntities() {
    return Collections.<Class<?>>singletonList(TinyUrl.class);
  }

  @Override
  public String getChangelogLocation() {
    return "META-INF/add_deleted_email_column_V1.xml";
  }

  @Override
  public void close() {}

  @Override
  public String getFactoryId() {
    return TinyUrlEntityProviderFactory.ID;
  }
}
