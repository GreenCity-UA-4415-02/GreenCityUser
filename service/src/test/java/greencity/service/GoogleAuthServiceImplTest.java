package greencity.service;

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
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GoogleAuthServiceImplTest {

    @Mock
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private GoogleAuthServiceImpl googleAuthService;

    private static final String CLIENT_ID = "dummy_client_id";
    private static final String REDIRECT_URI = "http://localhost:8060/auth/google/callback";
    private static final String SCOPE = "email,profile,openid";
    private static final String RESPONSE_TYPE = "code";
    private static final String AUTH_URI = "https://auth.google.com/auth";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(googleAuthService, "clientId", CLIENT_ID);
        ReflectionTestUtils.setField(googleAuthService, "redirectUri", REDIRECT_URI);
        ReflectionTestUtils.setField(googleAuthService, "scope", SCOPE);
        ReflectionTestUtils.setField(googleAuthService, "responseType", RESPONSE_TYPE);
        ReflectionTestUtils.setField(googleAuthService, "authorizationUri", AUTH_URI);
    }

    @Test
    @DisplayName("Returns correct URI for redirection + saves request to repository")
    void generateGoogleAuthRedirectUrl_ReturnCorrectUrl_And_SaveRequest() {
        URI url = googleAuthService.generateGoogleAuthRedirectUrl(request, response);

        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(url);
        Map<String, String> params = builder.build().getQueryParams().toSingleValueMap();

        assertEquals(CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID));
        assertEquals(REDIRECT_URI, params.get(OAuth2ParameterNames.REDIRECT_URI));
        assertEquals(SCOPE.replace(",", "%20"), params.get(OAuth2ParameterNames.SCOPE));
        assertEquals(RESPONSE_TYPE, params.get(OAuth2ParameterNames.RESPONSE_TYPE));

        String state = params.get(OAuth2ParameterNames.STATE);
        assertNotNull(state);

        ArgumentCaptor<OAuth2AuthorizationRequest> authRequestCaptor =
                ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
        verify(authorizationRequestRepository).saveAuthorizationRequest(
                authRequestCaptor.capture(), eq(request), eq(response));

        OAuth2AuthorizationRequest savedRequest = authRequestCaptor.getValue();
        assertEquals(state, savedRequest.getState());
    }
}
