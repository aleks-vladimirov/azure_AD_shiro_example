package info.vladimirov.azure.filter.shiro.authentication;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;

import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
public class IdTokenClaims implements Serializable {

    private static final long serialVersionUID = 421_23L;

    private List<String> groups = new ArrayList<>();
    private List<String> roles = new ArrayList<>();
    private IAccount account;
    private Map<String, Object> idTokenClaims;
    private boolean groupsOverage = false;


    public IdTokenClaims(IAuthenticationResult authResult) throws ParseException {
        this.account = authResult.account();
        final Map<String, Object> tokenClaims = SignedJWT.parse(authResult.idToken()).getJWTClaimsSet().getClaims();
        this.idTokenClaims = tokenClaims;
        setGroupsFromIdToken(tokenClaims);
        setRolesFromIdToken(idTokenClaims);
    }

    private void setGroupsFromIdToken(Map<String,Object> idTokenClaims) {

        JSONArray groupsFromToken = (JSONArray)this.idTokenClaims.get("groups");
        if (groupsFromToken != null) {
            this.groupsOverage = false;
            this.groups = new ArrayList<>();
            groupsFromToken.forEach(elem -> this.groups.add((String)elem));
        } else {
            // check for potential groups overage scenario!
            JSONObject jsonObj = (JSONObject)idTokenClaims.get("_claim_names");
            if (jsonObj != null && jsonObj.containsKey("groups")) {
                // overage scenario exists, handle it:
                this.groupsOverage = true;
            }
        }
    }


    private void setRolesFromIdToken(Map<String,Object> idTokenClaims) {
        JSONArray rolesFromToken = (JSONArray)idTokenClaims.get("roles");
        if (rolesFromToken != null) {
            this.groups = new ArrayList<>();
            rolesFromToken.forEach(elem -> this.roles.add((String)elem));
        }
    }

    @Override
    public String toString() {
        return account.username();
    }
}
