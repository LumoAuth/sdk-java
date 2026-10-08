package io.lumoauth;

/**
 * What {@link DelegationChain} needs from an agent: a token source plus the
 * OAuth client credentials the consent-code exchange and revocation require.
 * {@link LumoAgent} satisfies it.
 */
public interface ConfidentialClient extends TokenSource {
    String clientId();

    String clientSecret();
}
