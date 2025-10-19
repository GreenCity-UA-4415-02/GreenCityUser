package greencity.service;

import greencity.dto.user.GoogleSuccessSignInDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.net.URI;

public interface GoogleAuthService {

    URI generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response);

    GoogleSuccessSignInDto handleGoogleAuthCallback(String code, String state, String error,
                                                    HttpServletRequest request, HttpServletResponse response);
}
