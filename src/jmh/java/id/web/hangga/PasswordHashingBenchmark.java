package id.web.hangga;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.mindrot.jbcrypt.BCrypt;
import org.openjdk.jmh.annotations.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import com.lambdaworks.crypto.SCrypt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class PasswordHashingBenchmark {

    private static final String password = "Bismillah!@#123!";

    private byte[] generateSalt16Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return salt;
    }

    // BCrypt Benchmark
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(1)
    public void benchmarkBCrypt() {
        int cost = 12;
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(cost));
        BCrypt.checkpw(password, hashedPassword);
    }

    // SCrypt Benchmark
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(1)
    public void benchmarkScrypt() throws Exception {
        int N = 16384;
        int r = 8;
        int p = 1;
        int dkLen = 64;
        byte[] salt = generateSalt16Byte();
        byte[] hashedPassword = SCrypt.scrypt(password.getBytes(), salt, N, r, p, dkLen);
        byte[] attempt = SCrypt.scrypt(password.getBytes(), salt, N, r, p, dkLen);
    }

    // Argon2 Benchmark using Spring Security
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(1)
    public void benchmarkArgon2SpringSecurity() {
        Argon2PasswordEncoder argon2 = new Argon2PasswordEncoder(16, 32, 1, 60000, 10);
        String hash = argon2.encode(password);
        argon2.matches(password, hash);
    }

    // Argon2 Benchmark using BouncyCastle
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(1)
    public void benchmarkArgon2BouncyCastle() {
        byte[] salt = generateSalt16Byte();

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

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());
        byte[] result = new byte[hashLength];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
    }
}
