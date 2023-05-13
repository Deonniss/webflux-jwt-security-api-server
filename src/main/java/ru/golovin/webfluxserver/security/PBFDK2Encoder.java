package ru.golovin.webfluxserver.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class PBFDK2Encoder implements PasswordEncoder {

    private static final String SECRET_KEY_INSTANCE = "PBKDF2WithHmacSHA512";

    @Value("${jwt.password.encoder.secret}")
    private String secret;
    @Value("${jwt.password.encoder.iteration}")
    private int iteration;
    @Value("${jwt.password.encoder.keyLength}")
    private int keyLength;

    @Override
    public String encode(CharSequence rawPassword) {
        try {
            return Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance(SECRET_KEY_INSTANCE)
                    .generateSecret(new PBEKeySpec(rawPassword.toString().toCharArray(),
                            secret.getBytes(), iteration, keyLength)).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }
}
