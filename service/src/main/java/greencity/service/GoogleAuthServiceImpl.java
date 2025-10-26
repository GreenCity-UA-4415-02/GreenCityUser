package greencity.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.dto.user.GoogleUserDto;
import greencity.exception.exceptions.*;
import greencity.security.dto.SuccessSignInDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class GoogleAuthServiceImpl implements GoogleAuthService {
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.authorization-grant-type}")
    private String grantType;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.google.scope}")
    private String scope;

    @Value("${spring.security.oauth2.client.registration.google.response-type}")
    private String responseType;

    @Value("${spring.security.oauth2.client.provider.google.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String tokenUri;

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    private final GoogleProvisioningService provisioningService;
    private final SecureRandom secureRandom = new SecureRandom();
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final RestTemplate restTemplate;

    @Autowired
    public GoogleAuthServiceImpl(
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
        ModelMapper modelMapper,
        GoogleProvisioningService provisioningService,
        GoogleIdTokenVerifier googleIdTokenVerifier,
        RestTemplate restTemplate) {
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.provisioningService = provisioningService;
        this.googleIdTokenVerifier = googleIdTokenVerifier;
        this.restTemplate = restTemplate;
    }

    private String getFormattedScope(String scope) {
        return scope.replace(",", " ");
    }

    private String generateState() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private OAuth2AuthorizationRequest buildAuthorizationRequest(String state) {
        return OAuth2AuthorizationRequest.authorizationCode()
            .clientId(clientId)
            .redirectUri(redirectUri)
            .scopes(Arrays.stream(scope.split(",")).map(String::trim).collect(Collectors.toSet()))
            .authorizationUri(authorizationUri)
            .attributes(Collections.singletonMap(
                OAuth2ParameterNames.REGISTRATION_ID, "google"))
            .state(state)
            .build();
    }

    @Override
    public URI generateGoogleAuthRedirectUrl(HttpServletRequest request, HttpServletResponse response) {
        String state = generateState();

        OAuth2AuthorizationRequest authorizationRequest = buildAuthorizationRequest(state);

        authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);

        String formattedScope = getFormattedScope(scope);

        return UriComponentsBuilder.fromUriString(authorizationUri)
            .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
            .queryParam(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
            .queryParam(OAuth2ParameterNames.SCOPE, formattedScope)
            .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, responseType)
            .queryParam(OAuth2ParameterNames.STATE, state)
            .encode()
            .build()
            .toUri();
    }

    @Override
    public SuccessSignInDto handleGoogleAuthCallback(
        String code,
        String state,
        String error,
        HttpServletRequest request,
        HttpServletResponse response) {
        if (error != null) {
            log.error("Google authentication error: {}", error);
            throw new GoogleAuthErrorNotNullException("Google authentication failed: " + error);
        }
        if (code == null) {
            throw new GoogleAuthMissingCodeException("Missing authorization code.");
        }
        OAuth2AuthorizationRequest savedRequest = authorizationRequestRepository
            .removeAuthorizationRequest(request, response);

        if (savedRequest == null || !savedRequest.getState().equals(state)) {
            log.error("State mismatch detected");
            throw new StateMismatchException("State parameter mismatch.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> tokenRequestParams = new LinkedMultiValueMap<>();
        tokenRequestParams.add("code", code);
        tokenRequestParams.add("client_id", clientId);
        tokenRequestParams.add("client_secret", clientSecret);
        tokenRequestParams.add("redirect_uri", redirectUri);
        tokenRequestParams.add("grant_type", grantType);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(tokenRequestParams, headers);

        TokenResponse tokenResponse;
        try {
            ResponseEntity<TokenResponse> responseEntity = restTemplate.postForEntity(
                tokenUri,
                requestEntity,
                TokenResponse.class);
            if (!responseEntity.getStatusCode().is2xxSuccessful() || responseEntity.getBody() == null) {
                log.error("Google token exchange failed with status: {}",
                    responseEntity.getStatusCode());
                throw new GoogleTokenExchangeException("Failed to exchange code for tokens.");
            }
            tokenResponse = responseEntity.getBody();
        } catch (RestClientException e) {
            log.error("HTTP error during Google token exchange", e);
            throw new GoogleTokenExchangeException("Invalid or expired code.");
        }

        String idTokenString = tokenResponse.getIdToken();
        if (idTokenString == null || idTokenString.isEmpty()) {
            throw new GoogleTokenValidationException("Token response missing id_token.");
        }

        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Google ID Token verification failed", e);
            throw new GoogleTokenValidationException("ID Token validation failed.");
        }
        if (idToken == null) {
            throw new GoogleTokenValidationException("Invalid ID Token received.");
        }

        GoogleIdToken.Payload payload = idToken.getPayload();

        Boolean emailVerified = (Boolean) payload.get("email_verified");
        if (emailVerified == null || !emailVerified) {
            throw new GoogleEmailNotVerifiedException("Unverified email.");
        }

        GoogleUserDto googleUserDto = GoogleUserDto.builder()
            .googleProviderId(payload.getSubject())
            .email(payload.getEmail())
            .emailVerified(emailVerified)
            .name((String) payload.get("name"))
            .picture((String) payload.get("picture"))
            .build();

        return provisioningService.provisionUser(googleUserDto);
    }

    @Getter
    @Setter
    public static class TokenResponse {
        @JsonProperty("id_token")
        private String idToken;
    }
}
