package greencity.security.controller;

import greencity.exception.exceptions.*;
import greencity.exception.handler.CustomExceptionHandler;
import greencity.security.dto.SuccessSignInDto;
import greencity.service.GoogleAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.net.URI;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Google Security Controller Tests")
class GoogleSecurityControllerTest {

    @Mock
    private GoogleAuthService googleAuthService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private MockMvc mockMvc;

    @InjectMocks
    private GoogleSecurityController googleSecurityController;

    private static final String AUTH_GOOGLE = "/auth/google";
    private static final String AUTH_GOOGLE_CALLBACK = "/auth/google/callback";
    private static final String VALID_CODE = "valid_code";
    private static final String VALID_STATE = "valid_state";
    private static final String ERROR = null;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(googleSecurityController)
            .setControllerAdvice(new CustomExceptionHandler(new DefaultErrorAttributes()))
            .build();
    }

    @Test
    @DisplayName("GET /auth/google -> Should return 302 redirect with Location header")
    void redirectToGoogleConsent_ShouldReturn302AndCorrectLocationHeader() throws Exception {
        final String expectedRedirectUrl =
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&state=random_state";

        when(googleAuthService.generateGoogleAuthRedirectUrl(any(HttpServletRequest.class),
            any(HttpServletResponse.class)))
                .thenReturn(URI.create(expectedRedirectUrl));

        mockMvc.perform(get(AUTH_GOOGLE))
            .andExpect(status().isFound())
            .andExpect(header().string(HttpHeaders.LOCATION, expectedRedirectUrl));

        verify(googleAuthService).generateGoogleAuthRedirectUrl(any(HttpServletRequest.class),
            any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("GET /auth/google/callback -> Should return 200 OK with SuccessSignInDto fields")
    void handleGoogleAuthCallback_HappyPath_ShouldReturn200() throws Exception {
        SuccessSignInDto mockSignInDto = new SuccessSignInDto(
            1L,
            "dummy_access_token",
            "dummy_refresh_token",
            "Test User",
            false);
        when(googleAuthService.handleGoogleAuthCallback(
            eq(VALID_CODE), eq(VALID_STATE), eq(ERROR),
            any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(mockSignInDto);

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", VALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userId").value(1L))
            .andExpect(jsonPath("$.accessToken").value("dummy_access_token"))
            .andExpect(jsonPath("$.refreshToken").value("dummy_refresh_token"))
            .andExpect(jsonPath("$.name").value("Test User"))
            .andExpect(jsonPath("$.ownRegistrations").value(false));

        verify(googleAuthService).handleGoogleAuthCallback(
            eq(VALID_CODE), eq(VALID_STATE), eq(ERROR),
            any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    @DisplayName("GET /auth/google/callback Google Error Parameter -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_GoogleError_ShouldReturn400() throws Exception {
        final String INVALID_ERROR = "access_denied";
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new GoogleAuthErrorNotNullException("Unverified email."));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", VALID_STATE)
            .param("error", INVALID_ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /auth/google/callback Invalid Code -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_InvalidCode_ShouldReturn400() throws Exception {
        final String INVALID_CODE = null;
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new GoogleAuthMissingCodeException("Code error"));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", INVALID_CODE)
            .param("state", VALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /auth/google/callback State Mismatch -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_StateMismatch_ShouldReturn400() throws Exception {
        final String INVALID_STATE = "invalid_state";
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new StateMismatchException("State error"));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", INVALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /auth/google/callback Google Token Exchange -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_GoogleTokenExchangeException_ShouldReturn400() throws Exception {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new GoogleTokenExchangeException("Token exchange error"));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", VALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /auth/google/callback Google Token Validation -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_GoogleTokenValidationException_ShouldReturn400() throws Exception {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new GoogleTokenValidationException("Token validation error"));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", VALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /auth/google/callback Unverified Email -> Should throw 400 Bad Request")
    void handleGoogleAuthCallback_UnverifiedEmail_ShouldReturn400() throws Exception {
        when(googleAuthService.handleGoogleAuthCallback(any(), any(), any(), any(), any()))
            .thenThrow(new GoogleEmailNotVerifiedException("Unverified email."));

        mockMvc.perform(get(AUTH_GOOGLE_CALLBACK)
            .param("code", VALID_CODE)
            .param("state", VALID_STATE)
            .param("error", ERROR))
            .andExpect(status().isBadRequest());

        verify(googleAuthService).handleGoogleAuthCallback(any(), any(), any(), any(), any());
    }
}