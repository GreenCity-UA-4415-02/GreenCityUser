package greencity.dto.user;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleUserDto {
    private String googleProviderId;
    private String email;
    private Boolean emailVerified;
    private String name;
    private String picture;
}
