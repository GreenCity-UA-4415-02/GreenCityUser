package greencity.security.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.dto.user.GoogleUserDto;
import greencity.exception.exceptions.*;
import greencity.security.dto.SuccessSignInDto;
import greencity.service.GoogleAuthServiceImpl;
import greencity.service.GoogleProvisioningService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoSettings;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("Google Authentication Service Integration Tests")
class GoogleAuthServiceImplTest {

    @Mock
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    @Mock
    private GoogleIdTokenVerifier googleIdTokenVerifier;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private GoogleProvisioningService provisioningService;
    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private GoogleAuthServiceImpl googleAuthService;

    private static final String CLIENT_ID = "dummy_client_id";
    private static final String CLIENT_SECRET = "dummy_client_secret";
    private static final String REDIRECT_URI = "http://localhost:8060/auth/google/callback";
    private static final String SCOPE = "email,profile,openid";
    private static final String RESPONSE_TYPE = "code";
    private static final String AUTH_URI = "https://auth.google.com/auth";
    private static final String TOKEN_URI = "https://token.google.com/token";

    private static final String VALID_CODE = "valid_auth_code";
    private static final String VALID_STATE = "valid_state";
    private static final String ERROR = null;
    private static final String ID_TOKEN_STRING = "mock.jwt.idtoken";

    private GoogleIdToken mockIdToken;
    private GoogleIdToken.Payload mockPayload;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException {
        ReflectionTestUtils.setField(googleAuthService, "clientId", CLIENT_ID);
        ReflectionTestUtils.setField(googleAuthService, "clientSecret", CLIENT_SECRET);
        ReflectionTestUtils.setField(googleAuthService, "redirectUri", REDIRECT_URI);
        ReflectionTestUtils.setField(googleAuthService, "scope", SCOPE);
        ReflectionTestUtils.setField(googleAuthService, "responseType", RESPONSE_TYPE);
        ReflectionTestUtils.setField(googleAuthService, "grantType", "authorization_code");
        ReflectionTestUtils.setField(googleAuthService, "authorizationUri", AUTH_URI);
        ReflectionTestUtils.setField(googleAuthService, "tokenUri", TOKEN_URI);

        ReflectionTestUtils.setField(googleAuthService, "restTemplate", restTemplate);

        mockPayload = new GoogleIdToken.Payload();
        mockPayload.setSubject("1234567890");
        mockPayload.setEmail("user@example.com");
        mockPayload.setEmailVerified(true);
        mockPayload.put("name", "Test User");
        mockPayload.put("picture", "http://example.com/pic.jpg");

        mockIdToken = mock(GoogleIdToken.class);
        when(mockIdToken.getPayload()).thenReturn(mockPayload);

        when(googleIdTokenVerifier.verify(ID_TOKEN_STRING)).thenReturn(mockIdToken);

        OAuth2AuthorizationRequest savedRequest = OAuth2AuthorizationRequest.authorizationCode()
            .state(VALID_STATE).authorizationUri(AUTH_URI).clientId(CLIENT_ID)
            .redirectUri(REDIRECT_URI).scopes(Collections.emptySet()).build();

        when(authorizationRequestRepository.removeAuthorizationRequest(request, response))
            .thenReturn(savedRequest);

        GoogleAuthServiceImpl.TokenResponse tokenResponse = new GoogleAuthServiceImpl.TokenResponse();
        tokenResponse.setIdToken(ID_TOKEN_STRING);

        when(restTemplate.postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class)))
            .thenReturn(ResponseEntity.ok(tokenResponse));
    }

    @Test
    @DisplayName("Generate Redirect URL: Should save request and return correct URL")
    void generateGoogleAuthRedirectUrl_ShouldSaveRequestAndReturnCorrectUrl() {
        URI uri = googleAuthService.generateGoogleAuthRedirectUrl(request, response);
        String url = uri.toString();
        assertFalse(url.contains(" "), "URL must NOT contain unencoded spaces; encoding is required.");

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        Map<String, String> params = builder.build().getQueryParams().toSingleValueMap();

        assertEquals(CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID));
        assertEquals(REDIRECT_URI, params.get(OAuth2ParameterNames.REDIRECT_URI));
        assertEquals(SCOPE.replace(",", "%20"), params.get(OAuth2ParameterNames.SCOPE));
        assertEquals(RESPONSE_TYPE, params.get(OAuth2ParameterNames.RESPONSE_TYPE));

        String state = params.get(OAuth2ParameterNames.STATE);
        assertNotNull(state, "The state parameter must be present in the URL.");

        ArgumentCaptor<OAuth2AuthorizationRequest> authRequestCaptor =
            ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);

        verify(authorizationRequestRepository).saveAuthorizationRequest(
            authRequestCaptor.capture(), eq(request), eq(response));

        OAuth2AuthorizationRequest savedRequest = authRequestCaptor.getValue();
        assertEquals(state, savedRequest.getState(),
            "The state parameter in the URL must match the state saved in the repository.");
    }

    @Test
    @DisplayName("Callback: Happy Path - Should exchange code, validate token, and return user data")
    void handleGoogleAuthCallback_HappyPath() throws GeneralSecurityException, IOException {
        SuccessSignInDto expectedSignInDto = new SuccessSignInDto(
            1L, "mockAccessToken", "mockRefreshToken", "Test User", true);

        when(provisioningService.provisionUser(any(GoogleUserDto.class)))
            .thenReturn(expectedSignInDto);

        SuccessSignInDto result =
            googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, ERROR, request, response);

        assertNotNull(result);
        assertEquals(expectedSignInDto, result);
        assertEquals("mockAccessToken", result.getAccessToken());
        assertEquals(1L, result.getUserId());

        verify(authorizationRequestRepository).removeAuthorizationRequest(request, response);
        verify(googleIdTokenVerifier).verify(ID_TOKEN_STRING);
        verify(restTemplate).postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class));

        ArgumentCaptor<GoogleUserDto> googleUserCaptor = ArgumentCaptor.forClass(GoogleUserDto.class);
        verify(provisioningService).provisionUser(googleUserCaptor.capture());

        GoogleUserDto capturedDto = googleUserCaptor.getValue();
        assertEquals("1234567890", capturedDto.getGoogleProviderId());
        assertEquals("user@example.com", capturedDto.getEmail());
        assertTrue(capturedDto.getEmailVerified());
        assertEquals("Test User", capturedDto.getName());
        assertEquals("http://example.com/pic.jpg", capturedDto.getPicture());
    }

    @Test
    @DisplayName("Callback: State Mismatch - Should throw StateMismatchException")
    void handleGoogleAuthCallback_StateMismatch_ShouldThrowException() {
        final String INVALID_STATE = "invalid_state";

        assertThrows(StateMismatchException.class,
            () -> googleAuthService.handleGoogleAuthCallback(VALID_CODE, INVALID_STATE, ERROR, request, response));

        verify(authorizationRequestRepository).removeAuthorizationRequest(request, response);
        verifyNoInteractions(restTemplate);
        verifyNoInteractions(googleIdTokenVerifier);
        verifyNoInteractions(provisioningService);
    }

    @Test
    @DisplayName("Callback: Error not null - Should throw GoogleAuthErrorNotNullException")
    void handleGoogleAuthCallback_GoogleAuthErrorNotNullException_ShouldThrowException() {
        final String INVALID_ERROR = "access_denied";

        assertThrows(GoogleAuthErrorNotNullException.class,
            () -> googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, INVALID_ERROR, request,
                response));

        verifyNoInteractions(authorizationRequestRepository);
        verifyNoInteractions(restTemplate);
        verifyNoInteractions(googleIdTokenVerifier);
        verifyNoInteractions(provisioningService);
    }

    @Test
    @DisplayName("Callback: Code is null - Should throw GoogleAuthMissingCodeException")
    void handleGoogleAuthCallback_GoogleAuthMissingCodeException_ShouldThrowException() {
        final String INVALID_CODE = null;

        assertThrows(GoogleAuthMissingCodeException.class,
            () -> googleAuthService.handleGoogleAuthCallback(INVALID_CODE, VALID_STATE, ERROR, request, response));

        verifyNoInteractions(authorizationRequestRepository);
        verifyNoInteractions(restTemplate);
        verifyNoInteractions(googleIdTokenVerifier);
        verifyNoInteractions(provisioningService);
    }

    @Test
    @DisplayName("Callback: Invalid Code - Should throw GoogleCodeExchangeException")
    void handleGoogleAuthCallback_InvalidCode_ShouldThrowException() throws GeneralSecurityException, IOException {
        when(restTemplate.postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class)))
            .thenReturn(ResponseEntity.badRequest().build());

        assertThrows(GoogleTokenExchangeException.class,
            () -> googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, ERROR, request, response));

        verify(authorizationRequestRepository).removeAuthorizationRequest(request, response);
        verify(restTemplate).postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class));
        verify(googleIdTokenVerifier, never()).verify(any(String.class));
        verifyNoInteractions(provisioningService);
    }

    @Test
    @DisplayName("Callback: Invalid ID Token Signature/Claims - Should throw GoogleTokenValidationException")
    void handleGoogleAuthCallback_InvalidIdToken_ShouldThrowException() throws GeneralSecurityException, IOException {
        when(googleIdTokenVerifier.verify(ID_TOKEN_STRING)).thenReturn(null);

        assertThrows(GoogleTokenValidationException.class,
            () -> googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, ERROR, request, response));

        verify(authorizationRequestRepository).removeAuthorizationRequest(request, response);
        verify(restTemplate).postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class));
        verify(googleIdTokenVerifier).verify(ID_TOKEN_STRING);
        verifyNoInteractions(provisioningService);
    }

    @Test
    @DisplayName("Callback: Unverified Email - Should throw EmailNotVerified")
    void handleGoogleAuthCallback_UnverifiedEmail_ShouldThrowException() throws GeneralSecurityException, IOException {
        mockPayload.setEmailVerified(false);

        GoogleEmailNotVerifiedException exception = assertThrows(GoogleEmailNotVerifiedException.class,
            () -> googleAuthService.handleGoogleAuthCallback(VALID_CODE, VALID_STATE, ERROR, request, response));

        assertTrue(exception.getMessage().contains("Unverified email"));

        verify(authorizationRequestRepository).removeAuthorizationRequest(request, response);
        verify(restTemplate).postForEntity(eq(TOKEN_URI), any(), eq(GoogleAuthServiceImpl.TokenResponse.class));
        verify(googleIdTokenVerifier).verify(ID_TOKEN_STRING);
        verifyNoInteractions(provisioningService);
    }
}
