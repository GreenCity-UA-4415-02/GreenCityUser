package greencity.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import greencity.constant.ErrorMessage;
import greencity.dto.user.GoogleSuccessSignInDto;
import greencity.dto.user.UserVO;
import greencity.enums.UserStatus;
import greencity.exception.exceptions.BadUserStatusException;
import greencity.repository.UserRepo;
import greencity.security.dto.SuccessSignUpDto;
import greencity.security.dto.ownsecurity.OwnSignUpDto;
import greencity.security.jwt.JwtTool;
import greencity.security.service.OwnSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
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
    private final UserRepo userRepo;
    private final ModelMapper modelMapper;
    private final OwnSecurityService ownSecurityService;
    private final JwtTool jwtTool;
    private final SecureRandom secureRandom = new SecureRandom();
    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final RestTemplate restTemplate;

    @Autowired
    public GoogleAuthServiceImpl(
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository,
            UserService userService, UserRepo userRepo, ModelMapper modelMapper, OwnSecurityService ownSecurityService, JwtTool jwtTool,
            GoogleIdTokenVerifier googleIdTokenVerifier) {
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.userRepo = userRepo;
        this.modelMapper = modelMapper;
        this.ownSecurityService = ownSecurityService;
        this.jwtTool = jwtTool;
        this.googleIdTokenVerifier = googleIdTokenVerifier;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(5000);
        this.restTemplate = new RestTemplate(factory);
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
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("access_type", "offline");

        return OAuth2AuthorizationRequest.authorizationCode()
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scopes(Arrays.stream(scope.split(",")).map(String::trim).collect(Collectors.toSet()))
                .authorizationUri(authorizationUri)
                .additionalParameters(additionalParameters)
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
    public GoogleSuccessSignInDto handleGoogleAuthCallback(
            String code,
            String state,
            String error,
            HttpServletRequest request,
            HttpServletResponse response) {
        if (error != null) {
            log.error("Google authentication error: {}", error);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Google authentication failed: " + error);
        }

        if (code == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing authorization code.");
        }
        OAuth2AuthorizationRequest savedRequest = authorizationRequestRepository
                .removeAuthorizationRequest(request, response);

        if (savedRequest == null || !savedRequest.getState().equals(state)) {
            log.error("State mismatch detected");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "State parameter mismatch.");
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
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to exchange code for tokens.");
            }
            tokenResponse = responseEntity.getBody();
        } catch (RestClientException e) {
            log.error("HTTP error during Google token exchange", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired code.");
        }

        String idTokenString = tokenResponse.getIdToken();
        if (idTokenString == null || idTokenString.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token response missing id_token.");
        }

        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Google ID Token verification failed", e);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ID Token validation failed.");
        }
        if (idToken == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid ID Token received.");
        }

        GoogleIdToken.Payload payload = idToken.getPayload();

        Boolean emailVerified = (Boolean) payload.get("email_verified");
        if (emailVerified == null || !emailVerified) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unverified email.");
        }

        Optional<UserVO> user = userRepo.findByEmail(payload.getEmail())
                .map(u -> modelMapper.map(u, UserVO.class));
        Long userId;

        if (!user.isEmpty()) {
            userId = user.get().getId();
        } else {
            ownSecurityService.signUp(OwnSignUpDto.builder()
                    .name((String) payload.get("name"))
                    .email(payload.getEmail())
                    .isUbs(false)
                    .password(UUID.randomUUID().toString())
                    .build(), "ua");
            user = userRepo.findByEmail(payload.getEmail())
                    .map(u -> modelMapper.map(u, UserVO.class));
            userId = user.get().getId();
        }

        String accessToken = jwtTool.createAccessToken(user.get().getEmail(), user.get().getRole());
        String refreshToken = jwtTool.createRefreshToken(user.get());

        return GoogleSuccessSignInDto.builder()
                .userId(userId)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .name((String) payload.get("name"))
                .googleUserId(payload.getSubject())
                .email(payload.getEmail())
                .emailVerified(emailVerified)
                .picture((String) payload.get("picture"))
                .build();
    }

    @Getter
    public static class TokenResponse {
        @JsonProperty("id_token")
        private String idToken;
    }
}
