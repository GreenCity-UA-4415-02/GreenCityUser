package greencity.service;

import greencity.security.dto.SuccessSignInDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;

public interface GoogleAuthService {
    URI generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response);

    SuccessSignInDto handleGoogleAuthCallback(String code, String state, String error,
        HttpServletRequest request, HttpServletResponse response);
}
