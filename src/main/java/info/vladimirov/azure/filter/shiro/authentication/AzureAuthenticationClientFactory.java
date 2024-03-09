package info.vladimirov.azure.filter.shiro.authentication;


import com.microsoft.aad.msal4j.*;

import java.net.MalformedURLException;
import java.util.Set;

public class AzureAuthenticationClientFactory {

    private String clientId;
    private String clientSecret;
    private String authority;
    private String redirectUri;
    private Set<String> scopes;


    public ConfidentialClientApplication getClientApplication() throws MalformedURLException {

        return ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(clientSecret)).
                authority(authority).
                build();
    }


    public AuthorizationRequestUrlParameters.Builder getAuthRequestParametersBuilder() {

        return AuthorizationRequestUrlParameters
                .builder(redirectUri, scopes).responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT);

    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }
}
