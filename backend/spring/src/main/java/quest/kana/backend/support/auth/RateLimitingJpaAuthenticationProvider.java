package quest.kana.backend.support.auth;

import java.time.Instant;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import quest.kana.backend.domain.auth.model.jpa.LoginEntity;
import quest.kana.backend.domain.auth.model.jpa.LoginRepository;

import static org.springframework.util.Assert.isInstanceOf;
import static org.springframework.util.StringUtils.hasText;
import static quest.kana.backend.support.error.ErrorCodes.*;

public class RateLimitingJpaAuthenticationProvider implements AuthenticationProvider {
    private static final int LOCK_TIME = 300;

    private final LoginRepository loginRepository;
    private final PasswordEncoder passwordEncoder;

    public RateLimitingJpaAuthenticationProvider(LoginRepository lr, PasswordEncoder pe) {
        this.loginRepository = lr;
        this.passwordEncoder = pe;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        isInstanceOf(UsernamePasswordAuthenticationToken.class, auth, E_UNSUPPORTED_AUTHENTICATION_TYPE);

        if (!hasText(auth.getName()))
            throw new AuthenticationCredentialsNotFoundException(E_EMPTY_USERNAME);

        if (!hasText((String) auth.getCredentials()))
            throw new AuthenticationCredentialsNotFoundException(E_EMPTY_PASSWORD);

        LoginEntity login = loginRepository.findByUsername(auth.getName())
            .orElseThrow(() -> new BadCredentialsException(E_UNKNOWN_USERNAME));

        if (login.isLocked() && login.getModified().plusSeconds(LOCK_TIME).isAfter(Instant.now())) {
            loginRepository.logLoginTry(login.getId());
            throw new LockedException(E_ACCOUNT_LOCKED);
        }

        if (!passwordEncoder.matches(auth.getCredentials().toString(), login.getPassword())) {
            loginRepository.logLoginFailure(login.getId());
            throw new BadCredentialsException(E_BAD_CREDENTIALS);
        }

        // unlock even if disabled
        loginRepository.logLoginSuccess(login.getId());

        if (!login.isEnabled())
            throw new DisabledException(E_ACCOUNT_DISABLED);

        var response = new UsernamePasswordAuthenticationToken(login, auth.getCredentials(), login.getAuthorities());
        response.setDetails(auth.getDetails());
        return response;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
