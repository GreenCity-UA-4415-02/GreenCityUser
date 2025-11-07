package greencity.service;

import greencity.dto.event.EventNotificationDto;
import greencity.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EventNotificationConsumer {
    private final EmailService emailService;
    private final UserRepo userRepo;

    /**
     * Processes event notifications received from RabbitMQ.
     *
     * @param notification The notification DTO containing event details.
     */
    @RabbitListener(queues = "${rabbitmq.event-notification-queue}")
    public void processNotification(EventNotificationDto notification) {
        log.info("Received event notification: {}", notification);

        userRepo.findByEmail(notification.getOrganizerEmail())
            .ifPresentOrElse(
                user -> {
                    String language = (user.getLanguage() != null) ? user.getLanguage().getCode() : "en";
                    emailService.sendEventNotification(
                        notification.getOrganizerName(),
                        notification.getOrganizerEmail(),
                        notification.getEventTitle(),
                        notification.getEventType().name(),
                        language);
                    log.info("Email notification for event '{}' sent to {}", notification.getEventTitle(),
                        user.getEmail());
                },
                () -> log.warn("User with email {} not found. Cannot send email notification.",
                    notification.getOrganizerEmail()));
    }
}