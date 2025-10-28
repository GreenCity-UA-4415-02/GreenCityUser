package greencity.security.controller;

import greencity.annotations.ApiLocale;
import greencity.security.dto.SuccessSignInDto;
import greencity.service.GoogleAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import java.net.URI;

@RestController
@Validated
@Slf4j
@Tag(name = "Google OAuth", description = "Endpoints to perform Google OAuth2 flow (redirect & callback)")
public class GoogleSecurityController {
    private final GoogleAuthService googleAuthService;

    public GoogleSecurityController(GoogleAuthService googleAuthService) {
        this.googleAuthService = googleAuthService;
    }

    @Operation(summary = "Redirect to Google consent with CSRF state",
        description = "Generates Google OAuth2 authorization URL including a CSRF state "
            + "and returns 302 with Location header.")
    @ApiResponses({
        @ApiResponse(responseCode = "302", description = "Redirect to Google OAuth URL",
            headers = {
                @Header(name = "Location", description = "Google Authorization URL",
                    schema = @Schema(type = "string", format = "uri"))
            },
            content = @Content)
    })
    @GetMapping("/auth/google")
    @ApiLocale
    public ResponseEntity<Void> redirectToGoogleConsent(HttpServletRequest request, HttpServletResponse response) {
        URI redirectUrl = googleAuthService.generateGoogleAuthRedirectUrl(request, response);

        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(redirectUrl)
            .build();
    }

    @Operation(summary = "Google OAuth2 Callback: exchange code for tokens, validate id_token and return sign in data.",
        description = "Callback endpoint that receives `code` and `state` from Google, "
            + "exchanges authorization code for tokens, validates ID token and returns sign-in DTO.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Successful authentication",
            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                schema = @Schema(implementation = SuccessSignInDto.class),
                examples = {
                    @ExampleObject(name = "successExample",
                        value = "{\"userId\":1,\"accessToken\":\"mock.access.token.jwt\",\"refreshToken\""
                            + ":\"mock.refresh.token.jwt\",\"name\":\"Test User\",\"ownRegistrations\":false}")
                })),
        @ApiResponse(responseCode = "400",
            description = "Invalid code, state mismatch, unverified email or client error",
            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                schema = @Schema(description = "Error object example",
                    example = "{\"timestamp\":\"2025-01-01T12:00:00Z\",\"status\":400,\"error\""
                        + ":\"Bad Request\",\"message\":\"State error\",\"path\":\"/auth/google/callback\"}"))),
    })
    @GetMapping(value = "/auth/google/callback", produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiLocale
    public ResponseEntity<SuccessSignInDto> handleGoogleAuthCallback(
        @Parameter(name = "code", description = "Authorization code from Google (present when user approved consent)",
            required = false) @RequestParam(name = "code", required = false) String code,
        @Parameter(name = "state", description = "CSRF state previously generated and stored in session/cookie",
            required = false) @RequestParam(name = "state", required = false) String state,
        @Parameter(name = "error", description = "If Google returned an error (for example `access_denied`)",
            required = false) @RequestParam(name = "error", required = false) String error,
        HttpServletRequest request,
        HttpServletResponse response) {
        SuccessSignInDto signInDto = googleAuthService.handleGoogleAuthCallback(code, state, error, request, response);
        return ResponseEntity.ok(signInDto);
    }
}
