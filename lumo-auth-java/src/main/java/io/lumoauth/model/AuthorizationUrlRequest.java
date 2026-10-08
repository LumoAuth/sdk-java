package io.lumoauth.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parameters of an authorization-code redirect.
 *
 * <pre>{@code
 * AuthorizationUrlRequest.builder(clientId, "https://app.example.com/callback")
 *     .state(state).codeChallenge(challenge).build();
 * }</pre>
 */
public record AuthorizationUrlRequest(
    String clientId,
    String redirectUri,
    String scope,
    String state,
    String responseType,
    String codeChallenge,
    String codeChallengeMethod,
    String prompt,
    String accessType,
    Map<String, String> extra
) {
    public static final String DEFAULT_SCOPE = "openid profile email";

    public AuthorizationUrlRequest {
        extra = Models.map(extra);
    }

    public static Builder builder(String clientId, String redirectUri) {
        return new Builder(clientId, redirectUri);
    }

    public static final class Builder {
        private final String clientId;
        private final String redirectUri;
        private String scope;
        private String state;
        private String responseType;
        private String codeChallenge;
        private String codeChallengeMethod;
        private String prompt;
        private String accessType;
        private final Map<String, String> extra = new LinkedHashMap<>();

        private Builder(String clientId, String redirectUri) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
        }

        /** Defaults to {@link #DEFAULT_SCOPE}. */
        public Builder scope(String value) {
            this.scope = value;
            return this;
        }

        /** The CSRF token echoed back to the redirect URI. */
        public Builder state(String value) {
            this.state = value;
            return this;
        }

        /** Defaults to "code". */
        public Builder responseType(String value) {
            this.responseType = value;
            return this;
        }

        /** Enables PKCE; the method defaults to S256. */
        public Builder codeChallenge(String value) {
            this.codeChallenge = value;
            return this;
        }

        public Builder codeChallengeMethod(String value) {
            this.codeChallengeMethod = value;
            return this;
        }

        /** The OIDC prompt parameter ("consent", "login", "none"). */
        public Builder prompt(String value) {
            this.prompt = value;
            return this;
        }

        /** "offline" requests a refresh token. */
        public Builder accessType(String value) {
            this.accessType = value;
            return this;
        }

        /** An arbitrary extra query parameter. */
        public Builder extra(String name, String value) {
            this.extra.put(name, value);
            return this;
        }

        public AuthorizationUrlRequest build() {
            return new AuthorizationUrlRequest(clientId, redirectUri, scope, state, responseType,
                codeChallenge, codeChallengeMethod, prompt, accessType, extra);
        }
    }
}
