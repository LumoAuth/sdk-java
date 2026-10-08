package io.lumoauth.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code lumoauth.*} configuration. The top-level keys bind from the same
 * environment variables every LumoAuth SDK reads ({@code LUMOAUTH_URL},
 * {@code LUMOAUTH_ORG_ID}, {@code LUMOAUTH_API_KEY}) through Spring's relaxed binding.
 *
 * <pre>
 * lumoauth:
 *   url: https://app.lumoauth.dev
 *   org-id: acme-corp
 *   api-key: ${LUMOAUTH_API_KEY}
 *   login:
 *     client-id: lumo_abc
 *     client-secret: ${LUMOAUTH_CLIENT_SECRET}
 * </pre>
 */
@ConfigurationProperties(prefix = "lumoauth")
public class LumoAuthProperties {

    /** LumoAuth instance URL (US: https://app.lumoauth.dev, EU: https://eu.app.lumoauth.dev). */
    private String url;

    /** Organization slug, required for org-scoped calls (ABAC, agents, JIT, approvals, OAuth). */
    private String orgId;

    /** Organization API key, sent as X-API-Key. Without it the LumoAuth bean can only call unauthenticated endpoints. */
    private String apiKey;

    /** Per-request timeout. */
    private Duration timeout = Duration.ofSeconds(30);

    /** Disable TLS certificate verification. Local development against a self-signed instance only. */
    private boolean skipCertValidation;

    private final Agent agent = new Agent();
    private final Aauth aauth = new Aauth();
    private final Login login = new Login();
    private final Security security = new Security();

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getOrgId() {
        return orgId;
    }

    public void setOrgId(String orgId) {
        this.orgId = orgId;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    public boolean isSkipCertValidation() {
        return skipCertValidation;
    }

    public void setSkipCertValidation(boolean skipCertValidation) {
        this.skipCertValidation = skipCertValidation;
    }

    public Agent getAgent() {
        return agent;
    }

    public Aauth getAauth() {
        return aauth;
    }

    public Login getLogin() {
        return login;
    }

    public Security getSecurity() {
        return security;
    }

    /** The organization's OAuth / OIDC issuer: {@code {url}/orgs/{orgId}/api/v1}. */
    public String issuer() {
        String base = url == null || url.isBlank() ? io.lumoauth.LumoAuth.DEFAULT_BASE_URL : url;
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + "/orgs/" + orgId + "/api/v1";
    }

    /** An AI agent acting under its own OAuth client-credentials identity (creates a {@code LumoAgent} bean). */
    public static class Agent {
        /** The agent's OAuth client ID. Falls back to AGENT_CLIENT_ID. */
        private String clientId;
        /** The agent's OAuth client secret. Falls back to AGENT_CLIENT_SECRET. */
        private String clientSecret;
        /** Scopes requested at authentication; empty for the agent's registered defaults. */
        private List<String> scopes = new ArrayList<>();
        /** OAuth callback for the delegation consent flow. */
        private String redirectUri;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    /** An AAuth agent with a signing key (creates an {@code AAuthClient} bean). */
    public static class Aauth {
        /** The HTTPS URL uniquely identifying the agent. */
        private String agentIdentifier;
        /** The agent's Ed25519 (PKCS#8) or RSA private key, PEM. */
        private String privateKeyPem;
        /** The key ID registered with LumoAuth. */
        private String kid = "key-1";

        public String getAgentIdentifier() {
            return agentIdentifier;
        }

        public void setAgentIdentifier(String agentIdentifier) {
            this.agentIdentifier = agentIdentifier;
        }

        public String getPrivateKeyPem() {
            return privateKeyPem;
        }

        public void setPrivateKeyPem(String privateKeyPem) {
            this.privateKeyPem = privateKeyPem;
        }

        public String getKid() {
            return kid;
        }

        public void setKid(String kid) {
            this.kid = kid;
        }
    }

    /** Browser sign-in through Spring Security's OIDC login (creates a ClientRegistration named "lumoauth"). */
    public static class Login {
        /** The web application's OAuth client ID. Setting it enables login. */
        private String clientId;
        /** The client secret; omit for a public client, which relies on PKCE alone. */
        private String clientSecret;
        /** Requested scopes. */
        private List<String> scopes = new ArrayList<>(List.of("openid", "profile", "email"));
        /** The registration ID, which forms the login URL: /oauth2/authorization/{registration-id}. */
        private String registrationId = "lumoauth";
        /** Where users land after signing in, when the starter's default filter chain is used. */
        private String successUrl = "/";
        /** Paths everyone may reach without signing in, when the starter's default filter chain is used. */
        private List<String> permitAll = new ArrayList<>(List.of("/", "/error", "/favicon.ico"));
        /** Whether the starter contributes a default SecurityFilterChain (login + bearer tokens) when the app defines none. */
        private boolean defaultFilterChain = true;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public String getRegistrationId() {
            return registrationId;
        }

        public void setRegistrationId(String registrationId) {
            this.registrationId = registrationId;
        }

        public String getSuccessUrl() {
            return successUrl;
        }

        public void setSuccessUrl(String successUrl) {
            this.successUrl = successUrl;
        }

        public List<String> getPermitAll() {
            return permitAll;
        }

        public void setPermitAll(List<String> permitAll) {
            this.permitAll = permitAll;
        }

        public boolean isDefaultFilterChain() {
            return defaultFilterChain;
        }

        public void setDefaultFilterChain(boolean defaultFilterChain) {
            this.defaultFilterChain = defaultFilterChain;
        }
    }

    /** Spring Security integration for bearer tokens and method security. */
    public static class Security {
        /** Resolve LumoAuth bearer tokens to principals through the userinfo endpoint (OpaqueTokenIntrospector). */
        private boolean bearerTokens = true;
        /** Authority prefix for the roles claim. */
        private String roleAuthorityPrefix = "ROLE_";
        /** Authority prefix for agent capabilities. */
        private String capabilityAuthorityPrefix = "CAPABILITY_";
        /** Also list the principal's permissions during introspection and grant each as PERMISSION_{slug} (one extra request per token). */
        private boolean permissionsAsAuthorities;
        /** Authority prefix for permissions when permissions-as-authorities is on. */
        private String permissionAuthorityPrefix = "PERMISSION_";

        public boolean isBearerTokens() {
            return bearerTokens;
        }

        public void setBearerTokens(boolean bearerTokens) {
            this.bearerTokens = bearerTokens;
        }

        public String getRoleAuthorityPrefix() {
            return roleAuthorityPrefix;
        }

        public void setRoleAuthorityPrefix(String roleAuthorityPrefix) {
            this.roleAuthorityPrefix = roleAuthorityPrefix;
        }

        public String getCapabilityAuthorityPrefix() {
            return capabilityAuthorityPrefix;
        }

        public void setCapabilityAuthorityPrefix(String capabilityAuthorityPrefix) {
            this.capabilityAuthorityPrefix = capabilityAuthorityPrefix;
        }

        public boolean isPermissionsAsAuthorities() {
            return permissionsAsAuthorities;
        }

        public void setPermissionsAsAuthorities(boolean permissionsAsAuthorities) {
            this.permissionsAsAuthorities = permissionsAsAuthorities;
        }

        public String getPermissionAuthorityPrefix() {
            return permissionAuthorityPrefix;
        }

        public void setPermissionAuthorityPrefix(String permissionAuthorityPrefix) {
            this.permissionAuthorityPrefix = permissionAuthorityPrefix;
        }
    }
}
