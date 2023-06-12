package io.phasetwo.keycloak.magic.constants;

public interface TinyUrlConstants {
  String ACTION_TOKEN_URL_PATH = "login-actions/action-token";

  int NUMBER_OF_RETRIES_FOR_UNIQUE_URL_KEY = 10;

  long TINY_URL_CLEANUP_INTERVAL = 3600000;

  String ESD_UI = "esd-ui";

  String KC_ENV_KEY = "KC_ENV";

  String KC_ENV_PROD_VALUE = "prod";

  String ESD_MAGIC_LINK_FORMAT = "%slogin/%s";
}
