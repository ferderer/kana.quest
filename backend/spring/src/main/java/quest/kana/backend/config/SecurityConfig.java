package quest.kana.backend.config;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.util.StreamUtils.copyToString;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import quest.kana.backend.domain.auth.model.jpa.LoginRepository;
import quest.kana.backend.support.auth.RateLimitingJpaAuthenticationProvider;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${ui.url}")
    private String uiUrl;

    @Value("${self.url}")
    private String selfUrl;

    private final LoginRepository loginRepository;

    @Bean
    @Order(0)
    public SecurityFilterChain staticSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/_/**", "/favicon.ico")
            .authorizeHttpRequests(r -> r.anyRequest().permitAll())
            .requestCache(rc -> rc.disable())
            .securityContext(sc -> sc.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .cors(cors -> {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of(uiUrl));
                configuration.setAllowedHeaders(List.of("Accept", "Cache-Control", "If-Modified-Since"));
                configuration.setAllowedMethods(List.of("GET", "HEAD", "OPTIONS"));
                configuration.setAllowCredentials(false);
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                cors.configurationSource(source);
            })
            .build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/.well-known/**", "/oauth2/**", "/userinfo", "/connect/logout", "/login", "/default-ui.css")
            .cors(cors -> {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of(uiUrl));
                configuration.setAllowedHeaders(List.of("Accept", "Content-Type", "Authorization", "X-Requested-With", "Cookie"));
                configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
                configuration.setAllowCredentials(true); // Required for OAuth flows
                configuration.setMaxAge(1800L); // 30 minutes cache

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                cors.configurationSource(source);
            })
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("script-source 'none';form-action 'self';style-src 'self';base-uri 'self';frame-ancestors 'none';"))
                .frameOptions(frame -> frame.deny())
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN))
                .permissionsPolicyHeader(p -> p.policy("geolocation=(), microphone=(), camera=()"))
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .preload(true)
                    .maxAgeInSeconds(31536000)
                )
            )
            .authenticationProvider(authenticationProvider())
            .authorizeHttpRequests(registry -> registry
                .requestMatchers("/.well-known/**", "/oauth2/jwks", "/login", "/default-ui.css").permitAll()
                .anyRequest().authenticated()
            )
            .with(new OAuth2AuthorizationServerConfigurer().oidc(Customizer.withDefaults()), Customizer.withDefaults())
            .formLogin(configurer -> configurer
                .defaultSuccessUrl(uiUrl)
            )
            .logout(logout -> logout.disable())
            .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/api/**", "/error")
            .csrf(csrf -> csrf.disable())
            .cors(cors -> {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of(uiUrl));
                configuration.setAllowedHeaders(List.of("Accept", "Content-Type", "Authorization", "X-Requested-With", "Cache-Control"));
                configuration.setAllowedMethods(List.of("POST", "OPTIONS"));
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(1800L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/api/**", configuration);
                cors.configurationSource(source);
            })
            .headers(customizer -> customizer
                .xssProtection(xss -> xss.disable()) // irrelevant for JSON
                .contentTypeOptions(Customizer.withDefaults()) // adds X-Content-Type-Options: nosniff
                .frameOptions(frame -> frame.deny()) // no API inclusion in frames
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'"))
            )
            .authorizeHttpRequests(registry -> registry
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(handling -> handling
                .authenticationEntryPoint((req, res, auth) -> res.setStatus(401))
                .accessDeniedHandler((req, res, auth) -> res.setStatus(403))
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId("2f058b63-9175-4bd2-beea-a3938cc32f2f")
            .clientId("kana-quest")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri(uiUrl)
            .postLogoutRedirectUri(uiUrl)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(true)
                .build())
            .tokenSettings(TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(1))
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(false)
                .build()
            )
            .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws JOSEException, IOException {
        return new ImmutableJWKSet<>(new JWKSet(List.of(
            JWK.parseFromPEMEncodedObjects(copyToString(new ClassPathResource("keys/public.pem").getInputStream(), UTF_8)),
            JWK.parseFromPEMEncodedObjects(copyToString(new ClassPathResource("keys/private.pem").getInputStream(), UTF_8))
        )));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new RateLimitingJpaAuthenticationProvider(loginRepository, passwordEncoder());
    }
}
