package id.web.hangga;

import org.openjdk.jmh.annotations.*;
import org.mindrot.jbcrypt.BCrypt;
import com.lambdaworks.crypto.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
public class PasswordHashingBenchmark {

    private final String password = "Bismillah!@#123!";
    private byte[] salt16;

    @Setup(Level.Iteration)
    public void setup() {
        salt16 = new byte[16];
        new SecureRandom().nextBytes(salt16);
    }

    @Benchmark
    public String benchmarkBCryptHash() {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    @Benchmark
    public byte[] benchmarkSCryptHash() throws Exception {
        return SCrypt.scrypt(password.getBytes(), salt16, 16384, 8, 1, 64);
    }

    @Benchmark
    public byte[] benchmarkArgon2Hash() {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(2)
            .withMemoryAsKB(66536)
            .withParallelism(1)
            .withSalt(salt16);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] result = new byte[32];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);
        return result;
    }
}

