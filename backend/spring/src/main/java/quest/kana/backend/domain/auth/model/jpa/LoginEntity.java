package quest.kana.backend.domain.auth.model.jpa;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.NaturalId;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import quest.kana.backend.domain.auth.model.Role;

@Entity(name = "Login")
@Getter
@Setter
public class LoginEntity implements UserDetails {
    private static final int MAX_ATTEMPS = 3;

    @Id
    private Long id;

    @CreationTimestamp
    private Instant created;

    @UpdateTimestamp
    @Version
    private Instant modified = Instant.now();

    @Column(nullable = false)
    @Convert(converter = RolesConverter.class)
    private Set<Role> roles;

    @Column(nullable = false, unique = true, length = 50)
    @NotBlank
    private String username;

    @Column(nullable = false, unique = true, length = 320)
    @NaturalId(mutable = true)
    @NotBlank
    @Email
    private String email;

    private String password;
    private boolean enabled = true;
    private int failures = 0;
    
    @Override
    public boolean equals(Object obj) {
        return obj instanceof LoginEntity other && Objects.equals(id, other.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @JsonIgnore
    public boolean isLocked() {
        return failures >= MAX_ATTEMPS;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isLocked();
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
