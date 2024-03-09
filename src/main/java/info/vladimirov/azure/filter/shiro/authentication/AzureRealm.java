package info.vladimirov.azure.filter.shiro.authentication;

import com.microsoft.aad.msal4j.AuthorizationCodeParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


public class AzureRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(AzureRealm.class);
    private static final String ROLE_NAMES_DELIMETER = ",";

    private AzureAuthenticationClientFactory azureClientFactory;
    private Map<String, String> groupRolesMap;


    @Override
    public boolean supports(AuthenticationToken token) {
        if (token != null) {
            return token instanceof AzureAuthenticationCodeToken;
        }
        return false;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        AzureAuthenticationCodeToken authCodeToken = (AzureAuthenticationCodeToken) token;
        AuthenticationResponse authenticationResponse = authCodeToken.getAuthenticationResponse();
        final String nonce = authCodeToken.getNonce();
        if(nonce == null) {
            throw new AuthenticationException("Invalid state value in authentication code token");
        }

        if(authenticationResponse instanceof AuthenticationSuccessResponse) {

            AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authenticationResponse;
            validateAuthRespMatchesAuthCodeFlow(successResponse);

            IAuthenticationResult result = getAuthResultByAuthCode(successResponse);
            log.debug("ID Token returned: [{}]", result.idToken());
            validateNonce(nonce, result.idToken());
            return getAzureAuthenticationInfo(result);

        } else {
            AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authenticationResponse;
            throw new AuthenticationException(String.format("Request for auth code failed: %s - %s",
                    oidcResponse.getErrorObject().getCode(),
                    oidcResponse.getErrorObject().getDescription()));
        }

    }


    private SimpleAuthenticationInfo getAzureAuthenticationInfo(IAuthenticationResult result) {

        try {
            IdTokenClaims idTokenClaims = new IdTokenClaims(result);
            return new SimpleAuthenticationInfo(idTokenClaims.getAccount().username().replaceAll("@", "."),
                    result.accessToken(), getName());
        } catch (ParseException e) {
            throw new AuthenticationException("Cannot parse idToken", e);
        }

    }


    private void validateAuthRespMatchesAuthCodeFlow(AuthenticationSuccessResponse oidcResponse) throws AuthenticationException {
        if (oidcResponse.getIDToken() != null || oidcResponse.getAccessToken() != null ||
                oidcResponse.getAuthorizationCode() == null) {
            throw new AuthenticationException("Failed to validate data received from Authorization service - unexpected set of artifacts received");
        }
    }

    private IAuthenticationResult getAuthResultByAuthCode(AuthenticationSuccessResponse successResponse) {

        IAuthenticationResult result = null;
        ConfidentialClientApplication app;
        try {

            app = azureClientFactory.getClientApplication();

            String authCode = successResponse.getAuthorizationCode().getValue();
            AuthorizationCodeParameters parameters = AuthorizationCodeParameters.builder(
                            authCode,
                            successResponse.getRedirectionURI()).
                    build();

            Future<IAuthenticationResult> future = app.acquireToken(parameters);
            result = future.get();

        } catch (MalformedURLException | ExecutionException e) {
            throw new AuthenticationException("Azure - Cannot retrieve authentication result", e);
        } catch (InterruptedException e) {
            log.error("Getting authentication result interrupted", e);
            Thread.currentThread().interrupt();
        }

        if (result == null) {
            throw new AuthenticationException("Azure - Authentication result is null");
        }

        return result;
    }


    private void validateNonce(String nonceInRequest, String idToken) {

        try {
            String nonceInResponse = (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim("nonce");
            if (StringUtils.isEmpty(nonceInResponse) || !nonceInResponse.equals(nonceInRequest)) {
                throw new AuthenticationException("Invalid nonce in authentication code response");
            }
        } catch (ParseException e) {
            throw new AuthenticationException("Cannot get nonce from response", e);
        }

    }


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        IdTokenClaims idTokenClaims = (IdTokenClaims) getAvailablePrincipal(principals);
        List<String> groups = idTokenClaims.getGroups();
        log.info("User has the following groups: [{}]", String.join(", ", groups));
        if(log.isDebugEnabled()) {

        }

        return new SimpleAuthorizationInfo(getRoleNamesForGroups(groups));
    }


    protected Set<String> getRoleNamesForGroups(Collection<String> groupNames) {

        Set<String> roleNames = new HashSet<>(groupNames.size());

        if (groupRolesMap != null) {
            for (String groupName : groupNames) {
                String strRoleNames = groupRolesMap.get(groupName);
                if (strRoleNames != null) {
                    for (String roleName : strRoleNames.split(ROLE_NAMES_DELIMETER)) {
                        log.debug("User is member of group [{}] so adding role [{}}]", groupName, roleName);
                        roleNames.add(roleName);

                    }
                }
            }
        }
        return roleNames;
    }


    public Map<String, String> getGroupRolesMap() {
        return groupRolesMap;
    }

    public void setGroupRolesMap(Map<String, String> groupRolesMap) {
        this.groupRolesMap = groupRolesMap;
    }

    public void setAzureClientFactory(AzureAuthenticationClientFactory azureClientFactory) {
        this.azureClientFactory = azureClientFactory;
    }
}
