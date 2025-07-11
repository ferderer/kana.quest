package quest.kana.backend.domain.auth.model.jpa;

import static org.springframework.util.CollectionUtils.isEmpty;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import quest.kana.backend.domain.auth.model.Role;

@Converter
public class RolesConverter implements AttributeConverter<Set<Role>, Long> {

    @Override
    public Long convertToDatabaseColumn(Set<Role> set) {
        return isEmpty(set) ? 0 : set.stream().mapToLong(this::valueOf).sum();
    }

    @Override
    public Set<Role> convertToEntityAttribute(Long attr) {
        return attr == 0 ? Set.of() : EnumSet.copyOf(Arrays.stream(Role.values())
            .filter(enumValue -> (valueOf(enumValue) & attr) != 0)
            .toList());
    }

    /** Convert {@link app.vokabulix.server.api.authlogin.Role Role} to a single bit. */
    public long valueOf(Role value) {
        return switch(value) {
            case SYSTEM -> 1L;
            case ADMIN -> 2L;
            case CREATOR -> 4L;
            case USER -> 8L;
        };
    }
}
