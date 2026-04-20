package io.phasetwo.keycloak.magic.auth.cloudflare;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TurnstileAssessmentRequest {
  @JsonProperty("secret")
  private String secret;

  @JsonProperty("response")
  private String response;

  @JsonProperty("remoteip")
  private String remoteIp;

  public TurnstileAssessmentRequest(String secret, String response, String remoteIp) {
    this.secret = secret;
    this.response = response;
    this.remoteIp = remoteIp;
  }
}
