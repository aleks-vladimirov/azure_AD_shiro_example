package info.vladimirov.azure.filter.shiro.authentication;

public class AzureADLoginException extends RuntimeException {

    public AzureADLoginException(String message) {
        super(message);
    }

    public AzureADLoginException(String message, Throwable cause) {
        super(message, cause);
    }
}
