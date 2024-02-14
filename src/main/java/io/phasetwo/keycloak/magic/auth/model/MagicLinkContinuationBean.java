package io.phasetwo.keycloak.magic.auth.model;

public class MagicLinkContinuationBean {

  private final boolean sameBrowser;
  private final String url;

  public MagicLinkContinuationBean(boolean sameBrowser, String url) {
    this.sameBrowser = sameBrowser;
    this.url = url;
  }

  public boolean isSameBrowser() {
    return sameBrowser;
  }

  public String getUrl() {
    return url;
  }
}
