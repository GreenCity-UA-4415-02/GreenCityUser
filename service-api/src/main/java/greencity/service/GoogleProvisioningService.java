package greencity.service;

import greencity.dto.user.GoogleUserDto;
import greencity.security.dto.SuccessSignInDto;

public interface GoogleProvisioningService {
    SuccessSignInDto provisionUser(GoogleUserDto googleUserDto);
}
