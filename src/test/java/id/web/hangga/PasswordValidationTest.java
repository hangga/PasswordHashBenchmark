package id.web.hangga;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import com.lambdaworks.crypto.SCrypt;

public class PasswordValidationTest {

    String password = "Bismillah!@#123!";

    /**
     * This test demonstrates the use of BCrypt for password hashing and verification.
     * It includes:
     * 1. Hashing a password with a cost factor.
     * 2. Verifying the hashed password.
     * 3. Ensuring that hashing produces different results each time due to salting.
     * 4. Checking that an incorrect password fails verification.
     */
    @Test
    public void testBCryptHashAndVerify() {
        int cost = 12; // log rounds (e.g., 10, 12, 14)

        // 1. Hash the password
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(cost));

        // 2. Hash should verify successfully
        assertTrue(BCrypt.checkpw(password, hashedPassword));

        // 3. Different hash on each call (due to salt)
        String secondHash = BCrypt.hashpw(password, BCrypt.gensalt(cost));
        assertNotEquals(hashedPassword, secondHash);

        // 4. Wrong password fails to verify
        assertFalse(BCrypt.checkpw("WrongPassword", hashedPassword));
    }

    /**
     * This test demonstrates the use of SCrypt for password hashing and verification.
     * It includes:
     * 1. Hashing a password with SCrypt parameters.
     * 2. Verifying the hashed password.
     * 3. Ensuring that hashing produces different results each time due to salting.
     * 4. Checking that an incorrect password fails verification.
     */
    @Test
    public void testScryptHashAndVerify() throws GeneralSecurityException {
        // Scrypt parameters
        int N = 16384;
        int r = 8;
        int p = 1;
        int dkLen = 64; // output length in bytes

        // Generate random salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        // Hash the password
        byte[] hashedPassword = SCrypt.scrypt(password.getBytes(), salt, N, r, p, dkLen);

        // -- VALIDATION --

        // 1. Correct password should match
        byte[] attempt = SCrypt.scrypt(password.getBytes(), salt, N, r, p, dkLen);
        assertArrayEquals(hashedPassword, attempt);

        // 2. Different password should fail
        byte[] wrongAttempt = SCrypt.scrypt("WrongPassword".getBytes(), salt, N, r, p, dkLen);
        assertFalse(Arrays.equals(hashedPassword, wrongAttempt));

        // 3. Salt ensures different hash
        byte[] newSalt = new byte[16];
        new SecureRandom().nextBytes(newSalt);
        byte[] secondHash = SCrypt.scrypt(password.getBytes(), newSalt, N, r, p, dkLen);
        assertFalse(Arrays.equals(hashedPassword, secondHash));
    }

    /**
     * This test demonstrates the use of Argon2 for password hashing and verification.
     * It includes:
     * 1. Hashing a password with Argon2 parameters.
     * 2. Verifying the hashed password.
     * 3. Ensuring that hashing produces different results each time due to salting.
     * 4. Checking that an incorrect password fails verification.
     */
    @Test
    public void givenRawPassword_whenEncodedWithArgon2_thenMatchesEncodedPassword() {
        Argon2PasswordEncoder arg2SpringSecurity = new Argon2PasswordEncoder(16, 32, 1, 60000, 10);
        String springBouncyHash = arg2SpringSecurity.encode(password);

        assertTrue(arg2SpringSecurity.matches(password, springBouncyHash));
    }

    /**
     * Generates a random 16-byte salt using SecureRandom.
     *
     * @return A byte array representing the salt.
     */
    private byte[] generateSalt16Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);

        return salt;
    }

    /**
     * This test demonstrates the use of Argon2 for password hashing and verification.
     * It includes:
     * 1. Hashing a password with Argon2 parameters.
     * 2. Verifying the hashed password.
     * 3. Ensuring that hashing produces different results each time due to salting.
     * 4. Checking that an incorrect password fails verification.
     */
    @Test
    public void givenRawPasswordAndSalt_whenArgon2AlgorithmIsUsed_thenHashIsCorrect() {
        byte[] salt = generateSalt16Byte();
        String password = "Baeldung";

        int iterations = 2;
        int memLimit = 66536;
        int hashLength = 32;
        int parallelism = 1;

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memLimit)
            .withParallelism(parallelism)
            .withSalt(salt);

        Argon2BytesGenerator generate = new Argon2BytesGenerator();
        generate.init(builder.build());
        byte[] result = new byte[hashLength];
        generate.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);

        Argon2BytesGenerator verifier = new Argon2BytesGenerator();
        verifier.init(builder.build());
        byte[] testHash = new byte[hashLength];
        verifier.generateBytes(password.getBytes(StandardCharsets.UTF_8), testHash, 0, testHash.length);

        assertArrayEquals(result, testHash);
    }
}
