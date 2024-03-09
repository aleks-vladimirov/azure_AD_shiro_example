package info.vladimirov.azure.filter.shiro.authentication;

import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.RememberMeAuthenticationToken;

import java.util.Objects;

@Getter
@AllArgsConstructor
public class AzureAuthenticationCodeToken implements AuthenticationToken, RememberMeAuthenticationToken  {

	private transient AuthenticationResponse authenticationResponse;
	private String nonce;

	//Username
	@Override
	public Object getPrincipal() {
		return authenticationResponse;
	}

	@Override
	public Object getCredentials() {
		return authenticationResponse;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		AzureAuthenticationCodeToken that = (AzureAuthenticationCodeToken) o;
		return Objects.equals(authenticationResponse, that.authenticationResponse) && Objects.equals(nonce, that.nonce);
	}

	@Override
	public int hashCode() {
		return Objects.hash(authenticationResponse, nonce);
	}

	@Override
	public String toString() {
		return "AzureAuthenticationCodeToken{" +
				"authenticationResponse=" + authenticationResponse +
				", nonce='" + nonce + '\'' +
				'}';
	}

	@Override
	public boolean isRememberMe() {
		return true;
	}
}
