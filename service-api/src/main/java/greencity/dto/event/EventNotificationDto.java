package greencity.dto.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventNotificationDto implements Serializable {
    private Long eventId;
    private String eventTitle;
    private String organizerEmail;
    private String organizerName;
    private EventType eventType;
}