package io.phasetwo.keycloak.magic.auth.cloudflare;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TurnstileResponse {

  private boolean success;

  @JsonProperty("challenge_ts")
  private OffsetDateTime challengeTs;

  private String hostname;

  @JsonProperty("error-codes")
  private List<String> errorCodes;

  private String action;

  private String cdata;

  private Metadata metadata;

  public boolean isSuccess() {
    return success;
  }

  public void setSuccess(boolean success) {
    this.success = success;
  }

  public OffsetDateTime getChallengeTs() {
    return challengeTs;
  }

  public void setChallengeTs(OffsetDateTime challengeTs) {
    this.challengeTs = challengeTs;
  }

  public String getHostname() {
    return hostname;
  }

  public void setHostname(String hostname) {
    this.hostname = hostname;
  }

  public List<String> getErrorCodes() {
    return errorCodes;
  }

  public void setErrorCodes(List<String> errorCodes) {
    this.errorCodes = errorCodes;
  }

  public String getAction() {
    return action;
  }

  public void setAction(String action) {
    this.action = action;
  }

  public String getCdata() {
    return cdata;
  }

  public void setCdata(String cdata) {
    this.cdata = cdata;
  }

  public Metadata getMetadata() {
    return metadata;
  }

  public void setMetadata(Metadata metadata) {
    this.metadata = metadata;
  }

  public static class Metadata {
    @JsonProperty(value = "ephemeral_id", required = false)
    private String ephemeralId;

    @JsonProperty(value = "interactive", required = false)
    private String interactive;

    @JsonProperty(value = "result_with_testing_key", required = false)
    private String resultWithTestKey;

    public String getEphemeralId() {
      return ephemeralId;
    }

    public void setEphemeralId(String ephemeralId) {
      this.ephemeralId = ephemeralId;
    }

    public String getInteractive() {
      return interactive;
    }

    public void setInteractive(String interactive) {
      this.interactive = interactive;
    }

    public String getResultWithTestKey() {
        return resultWithTestKey;
    }

    public void setResultWithTestKey(String resultWithTestKey) {
        this.resultWithTestKey = resultWithTestKey;
    }
  }
}
