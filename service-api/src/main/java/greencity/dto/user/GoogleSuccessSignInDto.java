package greencity.dto.user;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleSuccessSignInDto {
    private Long userId;
    private String accessToken;
    private String refreshToken;
    private String name;
    private String googleUserId;
    private String email;
    private Boolean emailVerified;
    private String picture;
}
