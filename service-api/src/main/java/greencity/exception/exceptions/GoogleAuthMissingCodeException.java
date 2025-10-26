package greencity.exception.exceptions;

public class GoogleAuthMissingCodeException extends RuntimeException {
    public GoogleAuthMissingCodeException(String message) {
        super(message);
    }
}
