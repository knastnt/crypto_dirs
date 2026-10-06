package app;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Преобразует пароль пользователя в AES-ключ.
 *
 * <p>Пароль нельзя использовать как ключ напрямую: AES принимает ключ строго 16/24/32 байта,
 * а пароль может быть любой длины. Поэтому применяется PBKDF2-HMAC-SHA256 со случайной солью.
 * Соль и проверочное значение (HMAC от константы) сохраняются рядом с данными в файл
 * {@link #KEY_FILE_NAME}. Проверочное значение позволяет отличить неверный пароль от
 * повреждённых данных до начала расшифровки.
 */
public final class KeyDerivation {

    /** Имя файла с параметрами вывода ключа (соль + проверочное значение). */
    public static final String KEY_FILE_NAME = "8n732brTWmg-dyi3n_duo.tmp";

    private static final byte FORMAT_VERSION = 1;
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int ITERATIONS = 600_000;
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final byte[] VERIFIER_MESSAGE =
            "some-verifier-message-b64x3nzt_#@%Ui6)r".getBytes(StandardCharsets.UTF_8);

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyDerivation() {
    }

    /**
     * Генерирует новую соль, выводит ключ из пароля и сохраняет параметры в каталог.
     * Используется в режиме шифрования.
     */
    public static byte[] createKeyFile(Path dir, char[] password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);

        int iterations = ITERATIONS;
        byte[] key = deriveKey(password, salt, iterations);
        byte[] verifier = verifier(key);

        ByteBuffer buffer = ByteBuffer.allocate(1 + Integer.BYTES + SALT_LENGTH + verifier.length);
        buffer.put(FORMAT_VERSION);
        buffer.putInt(iterations);
        buffer.put(salt);
        buffer.put(verifier);

        Files.createDirectories(dir);
        Files.write(dir.resolve(KEY_FILE_NAME), buffer.array(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Arrays.fill(salt, (byte) 0);
        return key;
    }

    /**
     * Читает параметры из каталога, выводит ключ из пароля и сверяет проверочное значение.
     * Используется в режиме расшифровки.
     */
    public static byte[] loadKey(Path dir, char[] password) throws Exception {
        Path keyFile = dir.resolve(KEY_FILE_NAME);
        if (!Files.exists(keyFile)) {
            throw new IOException("Файл ключа не найден: " + keyFile
                    + ". Без него расшифровка невозможна.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(Files.readAllBytes(keyFile));
        if (buffer.remaining() < 1 + Integer.BYTES + SALT_LENGTH) {
            throw new IOException("Файл ключа повреждён: " + keyFile);
        }
        byte version = buffer.get();
        if (version != FORMAT_VERSION) {
            throw new IOException("Несовместимая версия файла ключа: " + version);
        }
        int iterations = buffer.getInt();
        if (iterations < 1) {
            throw new IOException("Некорректное число итераций в файле ключа: " + keyFile);
        }
        byte[] salt = new byte[SALT_LENGTH];
        buffer.get(salt);
        byte[] expected = new byte[buffer.remaining()];
        buffer.get(expected);

        byte[] key = deriveKey(password, salt, iterations);
        if (!MessageDigest.isEqual(expected, verifier(key))) {
            Arrays.fill(key, (byte) 0);
            throw new IllegalStateException("Неверный пароль.");
        }
        return key;
    }

    /** Выводит 256-битный AES-ключ из пароля и соли через PBKDF2. */
    public static byte[] deriveKey(char[] password, byte[] salt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        try {
            return SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] verifier(byte[] key) throws Exception {
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, MAC_ALGORITHM));
        return mac.doFinal(VERIFIER_MESSAGE);
    }
}
