package app;

import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class FileEncryptor {

    private static final String TRANSFORMATION = "AES/CTR/NoPadding";
    private static final int BUFFER_SIZE = 64 * 1024;
    private static final int IV_LENGTH = 16;
    static final String ENC_EXT = ".tmp";

    public static void processDir(Mode mode, Path sourceDir, Path targetDir, byte[] keyBytes) throws Exception {
        if (!Files.isDirectory(sourceDir)) {
            System.err.println("Source directory does not exist: " + sourceDir);
            System.exit(1);
        }
        Files.createDirectories(targetDir);

        NameCipher nameCipher = new NameCipher(keyBytes);
        Properties cryptoProps = new Properties();

        if (mode == Mode.ENCRYPT) {
            doEncrypt(sourceDir, targetDir, keyBytes, cryptoProps, nameCipher);
        } else {
            doDecrypt(sourceDir, targetDir, keyBytes, cryptoProps, nameCipher);
        }

        System.out.println("Done.");
    }

    // ---------- ШИФРОВАНИЕ ----------

    private static void doEncrypt(Path sourceDir, Path targetDir, byte[] keyBytes,
                                  Properties cryptoProps, NameCipher nameCipher) throws Exception {

        List<Path> files = new ArrayList<>();
        try (var stream = Files.walk(sourceDir)) {
            stream.filter(Files::isRegularFile).forEach(files::add);
        }

        int total = files.size();
        System.out.println("Найдено файлов: " + total);

        Map<String, String> index = new ConcurrentHashMap<>();

        int threadCount = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>(total);
        AtomicInteger counter = new AtomicInteger(0);

        for (Path file : files) {
            Future<?> future = executor.submit(() -> {
                try {
                    Path relative = sourceDir.relativize(file);

                    // Шифруем относительный путь целиком (все папки + имя файла)
                    String encRelative = nameCipher.encryptRelativePath(relative);
                    String encFileName = encRelative + ENC_EXT;

                    Path out = targetDir.resolve(encFileName);
                    encryptFile(file, out, keyBytes, cryptoProps);

                    // В индекс: зашифрованный путь -> оригинальный путь
                    index.put(encFileName, relative.toString());

                    System.out.println("[" + counter.incrementAndGet() + "/" + total + "]" + " OK ********* ->  " + encFileName);
                } catch (Exception e) {
                    System.out.println("[" + counter.incrementAndGet() + "/" + total + "]" + " FAIL " + file + ": " + e.getMessage());
                }
            });
            futures.add(future);
        }

        for (Future<?> f : futures) f.get();
        executor.shutdown();

        // Сохраняем зашифрованный индекс в корне целевой папки
        nameCipher.saveIndex(targetDir, index);

        System.out.println("Индекс сохранён: " + targetDir.resolve(nameCipher.indexFileName()));
    }

    // ---------- ДЕШИФРОВАНИЕ ----------

    private static void doDecrypt(Path sourceDir, Path targetDir, byte[] keyBytes,
                                  Properties cryptoProps, NameCipher nameCipher) throws Exception {

        // Загружаем индекс из корня sourceDir
        Map<String, String> index = nameCipher.loadIndex(sourceDir);
        if (index.isEmpty()) {
            System.err.println("Индекс не найден или пуст: " + sourceDir.resolve(nameCipher.indexFileName()));
            System.exit(1);
        }

        // Собираем список зашифрованных файлов (исключая сам индекс)
        String indexName = nameCipher.indexFileName();
        List<Path> files = new ArrayList<>();
        try (var stream = Files.walk(sourceDir)) {
            stream.filter(Files::isRegularFile)
                    .filter(p -> !p.getFileName().toString().equals(indexName))
                    .filter(p -> !p.getFileName().toString().equals(KeyDerivation.KEY_FILE_NAME))
                    .forEach(files::add);
        }

        int total = files.size();
        System.out.println("Найдено зашифрованных файлов: " + total);

        int threadCount = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>(total);
        AtomicInteger counter = new AtomicInteger(0);

        for (Path file : files) {
            Future<?> future = executor.submit(() -> {
                try {
                    Path relative = sourceDir.relativize(file);
                    String encRelative = relative.toString();

                    // Ищем оригинальный путь в индексе
                    String original = index.get(encRelative);
                    if (original == null) {
                        // На случай, если имя файла в индексе без .enc (не должно случаться)
                        throw new IOException("Нет записи в индексе для: " + encRelative);
                    }

                    Path originalPath = Path.of(original);
                    Path out = targetDir.resolve(originalPath);
                    decryptFile(file, out, keyBytes, cryptoProps);

                    System.out.println("[" + counter.incrementAndGet() + "/" + total + "]" + " OK " + encRelative + "  ->  *********");
                } catch (Exception e) {
                    System.out.println("[" + counter.incrementAndGet() + "/" + total + "]" + " FAIL " + file + ": " + e.getMessage());
                }
            });
            futures.add(future);
        }

        for (Future<?> f : futures) f.get();
        executor.shutdown();
    }

    // ---------- НИЗКОУРОВНЕВЫЕ ОПЕРАЦИИ ----------

    static void encryptFile(Path source, Path target, byte[] keyBytes, Properties props) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Files.createDirectories(target.getParent());

        try (InputStream in = Files.newInputStream(source);
             OutputStream rawOut = Files.newOutputStream(target,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

            rawOut.write(iv);

            try (CryptoOutputStream cryptoOut = new CryptoOutputStream(
                    TRANSFORMATION, props, rawOut, key, ivSpec)) {
                copy(in, cryptoOut);
            }
        }
    }

    private static void decryptFile(Path source, Path target, byte[] keyBytes, Properties props) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Files.createDirectories(target.getParent());

        try (InputStream rawIn = Files.newInputStream(source)) {
            byte[] iv = new byte[IV_LENGTH];
            int read = rawIn.readNBytes(iv, 0, IV_LENGTH);
            if (read != IV_LENGTH) {
                throw new IOException("Файл слишком короткий, IV отсутствует: " + source);
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            try (CryptoInputStream cryptoIn = new CryptoInputStream(
                    TRANSFORMATION, props, rawIn, key, ivSpec);
                 OutputStream out = Files.newOutputStream(target,
                         StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                copy(cryptoIn, out);
            }
        }
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
    }
}