package quest.kana.backend.domain.auth.model.jpa;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public interface LoginRepository extends JpaRepository<LoginEntity, Long> {

    @Query("from Login where email = :username or username = :username")
    Optional<LoginEntity> findByUsername(String username);

    @Transactional
    @Modifying
    @Query("update Login set modified = instant where id = :id")
    void logLoginTry(long id);

    @Transactional
    @Modifying
    @Query("update Login set modified = instant, failures = 0 where id = :id")
    void logLoginSuccess(long id);

    @Transactional
    @Modifying
    @Query("update Login set modified = instant, failures = failures + 1 where id = :id")
    void logLoginFailure(long id);
}
