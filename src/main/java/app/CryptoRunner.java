package app;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Запускает существующую стандартную логику: пароль -> ключ -> {@link FileEncryptor#processDir}.
 * Единственное место, где это делается, — режимы меню не дублируют этот код.
 */
public final class CryptoRunner {

    private CryptoRunner() {
    }

    public static void run(Mode mode, Path sourceDir, Path targetDir) throws Exception {
        if (mode == Mode.DECRYPT
                && !Files.isRegularFile(sourceDir.resolve(KeyDerivation.KEY_FILE_NAME))) {
            // Сообщение намеренно без пути: он может быть предустановленным и скрытым от пользователя.
            throw new IllegalStateException("В выбранном каталоге не найден файл ключа.");
        }

        char[] password = PasswordPrompt.read(mode == Mode.ENCRYPT);
        byte[] keyBytes;
        try {
            keyBytes = resolveKey(mode, sourceDir, targetDir, password);
        } finally {
            Arrays.fill(password, '\0');
        }

        try {
            FileEncryptor.processDir(mode, sourceDir, targetDir, keyBytes);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * При шифровании создаёт новую соль, при расшифровке читает сохранённую.
     */
    private static byte[] resolveKey(Mode mode, Path sourceDir, Path targetDir, char[] password)
            throws Exception {
        if (mode == Mode.ENCRYPT) {
            return KeyDerivation.createKeyFile(targetDir, password);
        }
        return KeyDerivation.loadKey(sourceDir, password);
    }
}
