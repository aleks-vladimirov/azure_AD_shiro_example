package info.vladimirov.azure.filter.shiro.filter;

import com.microsoft.aad.msal4j.AuthorizationRequestUrlParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import info.vladimirov.azure.filter.shiro.authentication.*;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static info.vladimirov.azure.filter.shiro.authentication.SessionManagementHelper.*;

public class AzureAuthenticationFilter extends AuthenticatingFilter {

    private static final Logger log = LoggerFactory.getLogger(AzureAuthenticationFilter.class);

    private AzureAuthenticationClientFactory azureClientFactory;

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (containsAuthenticationCode(httpRequest)) {
            return executeLogin(request, response);

        } else {
            SessionManagementHelper.storeURLPath(httpRequest.getSession(), httpRequest.getRequestURI());
            redirectToLogin(request, response);
            return false;
        }
    }

    private boolean containsAuthenticationCode(HttpServletRequest httpRequest) {

        Map<String, String[]> httpParameters = httpRequest.getParameterMap();

        boolean isPostRequest = httpRequest.getMethod().equalsIgnoreCase("POST");
        boolean containsErrorData = httpParameters.containsKey("error");
        boolean containIdToken = httpParameters.containsKey("id_token");
        boolean containsCode = httpParameters.containsKey("code");

        return (isPostRequest && containsErrorData) || containsCode || containIdToken;
    }

    @Override
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        try {

            final String state = UUID.randomUUID().toString();
            final String nonce = UUID.randomUUID().toString();
            ConfidentialClientApplication client = azureClientFactory.getClientApplication();
            AuthorizationRequestUrlParameters parameters = azureClientFactory.getAuthRequestParametersBuilder()
                    .state(state).nonce(nonce).build();
            SessionManagementHelper.storeStateAndNonceInSession(((HttpServletRequest) request).getSession(), state, nonce);

            final String authorizeUrl = client.getAuthorizationRequestUrl(parameters).toString();
            ((HttpServletResponse) response).sendRedirect(authorizeUrl);

        } catch (Exception e) {
            throw new AzureADLoginException("Azure - Cannot retrieve authentication code token", e);
        }
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {

        log.info("Login successful with the following parameters: " + subject.getPrincipals().getPrimaryPrincipal().toString());
        log.info("Is subject authenticated : " + SecurityUtils.getSubject().isAuthenticated());
        return true; //prevent any filter chaining on a success
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {

        log.error("Authentication failed", e);
        return true; //login failed, move to the next filter chain
    }

    public void setAzureClientFactory(AzureAuthenticationClientFactory azureClientFactory) {
        this.azureClientFactory = azureClientFactory;
    }

    @Override
    public boolean isAccessAllowed(ServletRequest request,
                                   ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        return subject.getPrincipal() != null;
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String currentUri = httpRequest.getRequestURL().toString();

        String[] statesParam = request.getParameterMap().get("state");
        // validate that state in response equals to state in request

        if (statesParam == null || statesParam.length != 1) {
            throw new AzureADLoginException("couldn't validate the session state param");
        }

        StateData stateData = SessionManagementHelper.removeStateFromSession(httpRequest.getSession(),
                statesParam[0]);

        final Map<String, List<String>> authParamConvert = new HashMap<>();

        request.getParameterMap().entrySet().stream().forEach(entr -> authParamConvert.put(entr.getKey(),
                Arrays.stream(entr.getValue()).collect(Collectors.toList())));


        AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(currentUri), authParamConvert);

        return new AzureAuthenticationCodeToken(authResponse, stateData != null ? stateData.getNonce() : null);
    }

}