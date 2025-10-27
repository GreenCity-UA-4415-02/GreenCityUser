package greencity.service;

import greencity.dto.user.GoogleUserDto;
import greencity.dto.user.UserVO;
import greencity.entity.Language;
import greencity.entity.User;
import greencity.enums.EmailNotification;
import greencity.enums.Role;
import greencity.enums.UserStatus;
import greencity.repository.LanguageRepo;
import greencity.repository.UserRepo;
import greencity.security.dto.SuccessSignInDto;
import greencity.security.jwt.JwtTool;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class GoogleProvisioningServiceImpl implements GoogleProvisioningService {
    private static final String GOOGLE_PROVIDER = "GOOGLE";
    private static final String DEFAULT_LANGUAGE_CODE = "en";
    private static final Double DEFAULT_RATING = 0.0;

    private final UserRepo userRepo;
    private final JwtTool jwtTool;
    private final ModelMapper modelMapper;
    private final LanguageRepo languageRepo;

    public GoogleProvisioningServiceImpl(UserRepo userRepo, JwtTool jwtTool, ModelMapper modelMapper,
        LanguageRepo languageRepo) {
        this.userRepo = userRepo;
        this.jwtTool = jwtTool;
        this.modelMapper = modelMapper;
        this.languageRepo = languageRepo;
    }

    @Override
    @Transactional
    public SuccessSignInDto provisionUser(GoogleUserDto dto) {
        Optional<User> linkedUser = userRepo.findByProviderAndProviderId(GOOGLE_PROVIDER, dto.getGoogleProviderId());

        if (linkedUser.isPresent()) {
            User user = linkedUser.get();
            updateUserProfile(user, dto);
            userRepo.save(user);
            return issueTokens(user, false);
        }

        Optional<User> userByEmail = userRepo.findByEmail(dto.getEmail());

        if (userByEmail.isPresent()) {
            User user = userByEmail.get();
            linkGoogleProvider(user, dto);
            userRepo.save(user);
            return issueTokens(user, true);
        }

        User newUser = createNewGoogleUser(dto);
        userRepo.save(newUser);
        return issueTokens(newUser, false);
    }

    private void updateUserProfile(User user, GoogleUserDto dto) {
        user.setEmailVerified(dto.getEmailVerified());
        if (dto.getName() != null && !dto.getName().isEmpty()) {
            user.setName(dto.getName());
        }
        if (dto.getPicture() != null && !dto.getPicture().isEmpty()) {
            user.setProfilePicturePath(dto.getPicture());
        }
        user.setLastActivityTime(LocalDateTime.now());
    }

    private void linkGoogleProvider(User user, GoogleUserDto dto) {
        user.setProvider(GOOGLE_PROVIDER);
        user.setProviderId(dto.getGoogleProviderId());
        user.setEmailVerified(dto.getEmailVerified());

        if (user.getProfilePicturePath() == null || user.getProfilePicturePath().isEmpty()) {
            user.setProfilePicturePath(dto.getPicture());
        }

        if (user.getName() == null || user.getName().isEmpty()) {
            user.setName(dto.getName());
        }
    }

    private User createNewGoogleUser(GoogleUserDto dto) {
        String refreshTokenKey = jwtTool.generateTokenKey();

        Language defaultLanguage = languageRepo.findByCode(DEFAULT_LANGUAGE_CODE)
            .orElseThrow(() -> new IllegalStateException("Language 'en' not found in database."));

        return User.builder()
            .name(dto.getName() != null ? dto.getName() : dto.getEmail().split("@")[0])
            .email(dto.getEmail())
            .dateOfRegistration(LocalDateTime.now())
            .role(Role.ROLE_USER)
            .refreshTokenKey(refreshTokenKey)
            .lastActivityTime(LocalDateTime.now())
            .userStatus(UserStatus.ACTIVATED)
            .emailNotification(EmailNotification.DISABLED)
            .rating(DEFAULT_RATING)
            .language(defaultLanguage)
            .uuid(UUID.randomUUID().toString())
            .provider(GOOGLE_PROVIDER)
            .providerId(dto.getGoogleProviderId())
            .emailVerified(dto.getEmailVerified())
            .profilePicturePath(dto.getPicture())
            .showLocation(true)
            .showEcoPlace(true)
            .showShoppingList(true)
            .build();
    }

    private SuccessSignInDto issueTokens(User user, boolean ownRegistrations) {
        String newRefreshTokenKey = jwtTool.generateTokenKey();
        user.setRefreshTokenKey(newRefreshTokenKey);

        UserVO userVO = modelMapper.map(user, UserVO.class);

        String accessToken = jwtTool.createAccessToken(userVO.getEmail(), userVO.getRole());
        String refreshToken = jwtTool.createRefreshToken(userVO);

        userRepo.save(user);

        return new SuccessSignInDto(
            user.getId(),
            accessToken,
            refreshToken,
            user.getName(),
            ownRegistrations);
    }
}