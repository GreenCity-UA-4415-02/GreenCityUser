package greencity.security.controller;

import greencity.annotations.ApiLocale;
import greencity.dto.user.GoogleSuccessSignInDto;
import greencity.service.GoogleAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
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
public class GoogleSecurityController {
    private final GoogleAuthService googleAuthService;

    public GoogleSecurityController(GoogleAuthService googleAuthService) {
        this.googleAuthService = googleAuthService;
    }

    @Operation(summary = "Redirect to Google consent with CSRF state")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirect to Google OAuth URL", headers = {
                    @Header(name = "Location", description = "Google Authorization URL")
            }),
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

    @Operation(summary = "Google OAuth2 Callback: exchange code for tokens, validate id_token and return sign in data.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful authentication"),
            @ApiResponse(responseCode = "400", description = "Invalid code, state mismatch, or unverified email"),
    })
    @GetMapping(value = "/auth/google/callback", produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiLocale
    public ResponseEntity<GoogleSuccessSignInDto> handleGoogleAuthCallback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            HttpServletRequest request,
            HttpServletResponse response) {
            GoogleSuccessSignInDto userDto = googleAuthService.handleGoogleAuthCallback(code, state, error, request, response);
            return ResponseEntity.ok(userDto);
    }
}
