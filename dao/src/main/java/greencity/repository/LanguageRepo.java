package greencity.repository;

import greencity.entity.Language;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface LanguageRepo extends JpaRepository<Language, Long> {
    Optional<Language> findByCode(String code);
}
