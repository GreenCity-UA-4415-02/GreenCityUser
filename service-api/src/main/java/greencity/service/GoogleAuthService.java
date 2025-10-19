package greencity.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;

public interface GoogleAuthService {
    URI generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response);
}
