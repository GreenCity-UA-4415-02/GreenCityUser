package greencity.service;

import greencity.dto.event.EventNotificationDto;
import greencity.dto.event.EventType;
import greencity.entity.Language;
import greencity.entity.User;
import greencity.repository.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class EventNotificationConsumerTest {

    @Mock
    private EmailService emailService;

    @Mock
    private UserRepo userRepo;

    @InjectMocks
    private EventNotificationConsumer consumer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void processNotification_ShouldSendEmail_WhenUserExists() {
        User user = new User();
        user.setEmail("test@greencity.com");
        Language lang = new Language();
        lang.setCode("ua");
        user.setLanguage(lang);

        EventNotificationDto dto = new EventNotificationDto();
        dto.setOrganizerName("Organizer");
        dto.setOrganizerEmail("test@greencity.com");
        dto.setEventTitle("Green Event");
        dto.setEventType(EventType.CREATED);

        when(userRepo.findByEmail("test@greencity.com")).thenReturn(Optional.of(user));


        consumer.processNotification(dto);

        verify(emailService, times(1)).sendEventNotification(
                eq("Organizer"),
                eq("test@greencity.com"),
                eq("Green Event"),
                eq("CREATED"),
                eq("ua")
        );
        verify(userRepo, times(1)).findByEmail("test@greencity.com");
    }

    @Test
    void processNotification_ShouldNotSendEmail_WhenUserNotFound() {

        EventNotificationDto dto = new EventNotificationDto();
        dto.setOrganizerName("Organizer");
        dto.setOrganizerEmail("notfound@greencity.com");
        dto.setEventTitle("Missing Event");
        dto.setEventType(EventType.DELETED);

        when(userRepo.findByEmail("notfound@greencity.com")).thenReturn(Optional.empty());


        consumer.processNotification(dto);


        verify(emailService, never()).sendEventNotification(any(), any(), any(), any(), any());
        verify(userRepo, times(1)).findByEmail("notfound@greencity.com");
    }

    @Test
    void processNotification_ShouldUseDefaultLanguage_WhenLanguageIsNull() {

        User user = new User();
        user.setEmail("nolanguage@greencity.com");
        user.setLanguage(null);

        EventNotificationDto dto = new EventNotificationDto();
        dto.setOrganizerName("NoLang Organizer");
        dto.setOrganizerEmail("nolanguage@greencity.com");
        dto.setEventTitle("Default Lang Event");
        dto.setEventType(EventType.EDITED);

        when(userRepo.findByEmail("nolanguage@greencity.com")).thenReturn(Optional.of(user));


        consumer.processNotification(dto);


        verify(emailService, times(1)).sendEventNotification(
                eq("NoLang Organizer"),
                eq("nolanguage@greencity.com"),
                eq("Default Lang Event"),
                eq("EDITED"),
                eq("en")
        );
    }
}
