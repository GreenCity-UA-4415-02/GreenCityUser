package greencity.security.service;

import greencity.dto.user.GoogleUserDto;
import greencity.entity.Language;
import greencity.repository.LanguageRepo;
import greencity.security.dto.SuccessSignInDto;
import greencity.entity.User;
import greencity.enums.Role;
import greencity.repository.UserRepo;
import greencity.security.jwt.JwtTool;
import greencity.dto.user.UserVO;
import greencity.service.GoogleProvisioningServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Google Provisioning Service Impl Tests")
class GoogleProvisioningServiceImplTest {

    @Mock
    private UserRepo userRepo;
    @Mock
    private JwtTool jwtTool;
    @Mock
    private ModelMapper modelMapper;
    @Mock
    private LanguageRepo languageRepo;

    @InjectMocks
    private GoogleProvisioningServiceImpl googleProvisioningService;

    private static final String PROVIDER = "GOOGLE";
    private static final String GOOGLE_SUB = "dummy_google_sub_123456789";
    private static final String GOOGLE_EMAIL = "google.user@gmail.com";
    private static final String GOOGLE_NAME = "Google User";
    private static final String GOOGLE_PROFILE_PIC = "http://profile.pic";

    private static final Long DUMMY_USER_ID = 1L;
    private static final String DUMMY_REFRESH_TOKEN_KEY = "mockRefreshTokenKey";
    private static final String DUMMY_ACCESS_TOKEN = "mockAccessToken";
    private static final String DUMMY_REFRESH_TOKEN = "mockRefreshToken";
    private static final String DEFAULT_LANGUAGE_CODE = "en";

    private GoogleUserDto googleUserDto;
    private UserVO userVo;
    private Language mockDefaultLanguage;

    @BeforeEach
    void setUp() {
        googleUserDto = GoogleUserDto.builder()
            .googleProviderId(GOOGLE_SUB)
            .email(GOOGLE_EMAIL)
            .name(GOOGLE_NAME)
            .picture(GOOGLE_PROFILE_PIC)
            .emailVerified(true)
            .build();

        userVo = UserVO.builder()
            .id(DUMMY_USER_ID)
            .email(GOOGLE_EMAIL)
            .role(Role.ROLE_USER)
            .refreshTokenKey(DUMMY_REFRESH_TOKEN_KEY)
            .build();

        mockDefaultLanguage = Language.builder().id(2L).code(DEFAULT_LANGUAGE_CODE).build();

        lenient().when(modelMapper.map(any(User.class), eq(UserVO.class))).thenReturn(userVo);
        lenient().when(jwtTool.createAccessToken(anyString(), any(Role.class)))
            .thenReturn(DUMMY_ACCESS_TOKEN);
        lenient().when(jwtTool.createRefreshToken(any(UserVO.class)))
            .thenReturn(DUMMY_REFRESH_TOKEN);
        lenient().when(jwtTool.generateTokenKey())
            .thenReturn(DUMMY_REFRESH_TOKEN_KEY);
    }

    private User createMockUser(Long id, boolean isLinked, String name) {
        return User.builder()
            .id(id)
            .email(GOOGLE_EMAIL)
            .name(name)
            .role(Role.ROLE_USER)
            .emailVerified(true)
            .provider(isLinked ? PROVIDER : null)
            .providerId(isLinked ? GOOGLE_SUB : null)
            .language(mockDefaultLanguage)
            .build();
    }

    private User createMockUser(Long id, boolean isLinked) {
        return createMockUser(id, isLinked, "Existing User");
    }

    @Test
    @DisplayName("Create new user if no match found by ID or Email (ownRegistrations=false)")
    void provisionUserAndIssueToken_CreateNewUser() {
        when(languageRepo.findByCode(DEFAULT_LANGUAGE_CODE))
            .thenReturn(Optional.of(mockDefaultLanguage));
        when(userRepo.findByProviderAndProviderId(PROVIDER, GOOGLE_SUB))
            .thenReturn(Optional.empty());
        when(userRepo.findByEmail(GOOGLE_EMAIL))
            .thenReturn(Optional.empty());
        when(userRepo.save(any(User.class))).thenAnswer(invocation -> {
            User newUser = invocation.getArgument(0);
            newUser.setId(DUMMY_USER_ID);
            return newUser;
        });

        SuccessSignInDto result = googleProvisioningService.provisionUser(googleUserDto);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepo, times(2)).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();
        assertEquals(GOOGLE_EMAIL, savedUser.getEmail());
        assertEquals(GOOGLE_NAME, savedUser.getName());
        assertEquals(PROVIDER, savedUser.getProvider());
        assertEquals(GOOGLE_SUB, savedUser.getProviderId());

        assertNotNull(savedUser.getLanguage());
        assertEquals(mockDefaultLanguage.getId(), savedUser.getLanguage().getId(),
            "The new user must be assigned the language ID fetched from the repository.");

        assertFalse(result.isOwnRegistrations(), "New user from Google should have ownRegistrations=false");

        verify(languageRepo, times(1)).findByCode(DEFAULT_LANGUAGE_CODE);
        verify(modelMapper, times(1)).map(any(User.class), eq(UserVO.class));
    }

    @Test
    @DisplayName("Link existing unlinked user found by Email (ownRegistrations=true)")
    void provisionUserAndIssueToken_LinkExistingUser() {
        final long existingUserId = 5L;
        User existingUnlinkedUser = createMockUser(existingUserId, false);

        when(userRepo.findByProviderAndProviderId(PROVIDER, GOOGLE_SUB))
            .thenReturn(Optional.empty());
        when(userRepo.findByEmail(GOOGLE_EMAIL))
            .thenReturn(Optional.of(existingUnlinkedUser));

        when(userRepo.save(any(User.class))).thenReturn(existingUnlinkedUser);

        SuccessSignInDto result = googleProvisioningService.provisionUser(googleUserDto);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepo, times(2)).save(userCaptor.capture());

        User updatedUser = userCaptor.getValue();
        assertEquals(existingUserId, updatedUser.getId());
        assertEquals(PROVIDER, updatedUser.getProvider(), "Provider must be set to GOOGLE.");
        assertEquals(GOOGLE_SUB, updatedUser.getProviderId(), "ProviderId must be set to Google SUB.");

        assertTrue(result.isOwnRegistrations(), "Linked user who was an original registrant should result in true.");

        verify(languageRepo, never()).findByCode(anyString());
        verify(modelMapper, times(1)).map(any(User.class), eq(UserVO.class));
    }

    @Test
    @DisplayName("Update existing linked user found by Provider ID (ownRegistrations=false)")
    void provisionUserAndIssueToken_UpdateExistingLinkedUser() {
        final long existingUserId = 7L;
        User existingLinkedUser = createMockUser(existingUserId, true, "Old Name");

        when(userRepo.findByProviderAndProviderId(PROVIDER, GOOGLE_SUB))
            .thenReturn(Optional.of(existingLinkedUser));

        when(userRepo.save(any(User.class))).thenReturn(existingLinkedUser);

        SuccessSignInDto result = googleProvisioningService.provisionUser(googleUserDto);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepo, times(2)).save(userCaptor.capture());

        User updatedUser = userCaptor.getValue();
        assertEquals(existingUserId, updatedUser.getId());
        assertEquals(GOOGLE_NAME, updatedUser.getName(), "User name should be updated from Google DTO.");

        assertFalse(result.isOwnRegistrations(), "Existing Google user should have ownRegistrations=false");

        verify(userRepo, never()).findByEmail(anyString());
        verify(languageRepo, never()).findByCode(anyString());
        verify(modelMapper, times(1)).map(any(User.class), eq(UserVO.class));
    }

    @Test
    @DisplayName("Prevent creation of duplicate records (finds existing linked user by ID) (ownRegistrations=false)")
    void provisionUserAndIssueToken_PreventDuplicateRecords() {
        final long existingUserId = 15L;
        User existingLinkedUser = createMockUser(existingUserId, true);

        when(userRepo.findByProviderAndProviderId(PROVIDER, GOOGLE_SUB))
            .thenReturn(Optional.of(existingLinkedUser));

        when(userRepo.save(any(User.class))).thenReturn(existingLinkedUser);

        SuccessSignInDto result = googleProvisioningService.provisionUser(googleUserDto);

        verify(userRepo, times(1)).findByProviderAndProviderId(PROVIDER, GOOGLE_SUB);

        verify(userRepo, times(2)).save(existingLinkedUser);

        assertEquals(existingUserId, result.getUserId());
        assertEquals("mockAccessToken", result.getAccessToken());
        assertFalse(result.isOwnRegistrations(), "Existing Google user should have ownRegistrations=false");

        verify(languageRepo, never()).findByCode(anyString());
        verify(modelMapper, times(1)).map(any(User.class), eq(UserVO.class));
    }

    @Test
    @DisplayName("Throw exception if default language 'en' is not found")
    void provisionUserAndIssueToken_LanguageNotFound_ThrowsException() {
        when(userRepo.findByProviderAndProviderId(PROVIDER, GOOGLE_SUB)).thenReturn(Optional.empty());
        when(userRepo.findByEmail(GOOGLE_EMAIL)).thenReturn(Optional.empty());

        when(languageRepo.findByCode(DEFAULT_LANGUAGE_CODE)).thenReturn(Optional.empty());

        IllegalStateException exception = assertThrows(IllegalStateException.class,
            () -> googleProvisioningService.provisionUser(googleUserDto));

        assertTrue(exception.getMessage().contains("Language 'en' not found"),
            "Exception message should indicate that the default language is missing.");

        verify(userRepo, never()).save(any(User.class));
    }
}