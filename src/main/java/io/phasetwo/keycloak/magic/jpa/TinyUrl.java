package io.phasetwo.keycloak.magic.jpa;

import com.j256.ormlite.field.DatabaseField;
import java.time.Instant;
import java.time.LocalDateTime;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.PrePersist;
import javax.persistence.Table;

@Entity
@Table(name="tiny_url")
@NamedQueries({ @NamedQuery(name = "findByUrlKey", query = "from TinyUrl where urlKey = :urlKey and realmId = :realmId") })
public class TinyUrl {

  @Id
  @Column(name = "id")
  private long id;

  @Column(name = "realm_id", nullable = false)
  private String realmId;

  @Column(name = "url_key", nullable = false)
  private String urlKey;

  @Column(name = "full_url", nullable = false)
  private String fullUrl;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @PrePersist
  public void prePersist() {
    createdAt = Instant.now();
  }
}
