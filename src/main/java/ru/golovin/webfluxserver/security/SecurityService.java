package ru.golovin.webfluxserver.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import ru.golovin.webfluxserver.entity.User;
import ru.golovin.webfluxserver.exception.AuthException;
import ru.golovin.webfluxserver.service.UserService;

import java.util.*;

@Service
@RequiredArgsConstructor
public class SecurityService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    public Mono<TokenDetails> authenticate(String username, String password) {
        return userService
                .getUserByUsername(username)
                .flatMap(user -> {
                    if (!user.isEnabled()) return Mono.error(new AuthException("Account disabled", "ACCOUNT_DISABLED"));
                    if (!passwordEncoder.matches(password, user.getPassword()))
                        return Mono.error(new AuthException("Incorrect password", "INCORRECT_PASSWORD"));
                    return Mono.just(generateToken(user).toBuilder().userId(user.getId()).build());
                })
                .switchIfEmpty(Mono.error(new AuthException("User not found", "USER_NOT_FOUND")));
    }

    private TokenDetails generateToken(User user) {
        Map<String, Object> claims = new HashMap<>() {{
            put("role", user.getRole());
            put("username", user.getUsername());
        }};
        return generateToken(claims, user.getId().toString());
    }

    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        long expirationTimeInMillis = expirationInSeconds * 1000L;
        Date expirationDate = new Date(new Date().getTime() + expirationTimeInMillis);
        return generateToken(expirationDate, claims, subject);
    }

    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {
        Date createdDate = new Date();
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(createdDate)
                .setId(UUID.randomUUID().toString())
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
                .compact();
        return TokenDetails.builder().token(token).issuedAt(createdDate).expiresAt(expirationDate).build();
    }
}
