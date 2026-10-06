package app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;

/**
 * Жизненный цикл расшифрованных данных (режим 3). Каталог расшифровки задаётся извне
 * (введён пользователем или предустановлен), но на время сеанса принадлежит приложению
 * и будет удалён целиком, поэтому он обязан быть пустым или несуществующим
 * ({@link #checkTarget}). Гарантии удаления:
 * <ul>
 *   <li>штатно — {@link #close()} (try-with-resources, в том числе при исключениях);</li>
 *   <li>Ctrl+C (SIGINT), SIGTERM, SIGHUP, закрытие окна консоли, выход из ОС,
 *       {@code System.exit(..)} (в т.ч. внутри {@link FileEncryptor}) — shutdown hook;</li>
 * </ul>
 * Пути в сообщениях не выводятся: они могут быть предустановленными и скрытыми.
 */
public final class DecryptionSession implements AutoCloseable {

    /** Маркер владения: при восстановлении удаляются только каталоги, где он есть. */
    static final String MARKER_NAME = ".fileenc-wipe-marker";
    private static final int MAX_ATTEMPTS = 3;

    private final Path directory;
    private final Thread shutdownHook;
    private boolean destroyed;

    private DecryptionSession(Path directory) {
        this.directory = directory;
        this.shutdownHook = new Thread(this::destroy, "decrypted-data-cleanup");
    }

    /**
     * Проверяет, что каталог можно безопасно отдать под полное удаление.
     *
     * @return текст ошибки без путей или пусто, если всё в порядке
     */
    public static Optional<String> checkTarget(Path source, Path target) {
        Path s = resolve(source);
        Path t = resolve(target);
        if (s.startsWith(t) || t.startsWith(s)) {
            return Optional.of("Зашифрованный и расшифрованный каталоги не должны совпадать "
                    + "или быть вложенными друг в друга.");
        }
        if (Files.exists(t)) {
            if (!Files.isDirectory(t)) {
                return Optional.of("Целевой путь не является каталогом.");
            }
            try (Stream<Path> children = Files.list(t)) {
                if (children.findAny().isPresent()) {
                    return Optional.of("Целевой каталог должен быть пустым: "
                            + "он будет полностью удалён при завершении.");
                }
            } catch (IOException e) {
                return Optional.of("Целевой каталог недоступен.");
            }
        }
        return Optional.empty();
    }

    /** Подготавливает каталог и сразу регистрирует очистку — до начала расшифровки. */
    public static DecryptionSession open(Path directory) throws IOException {
        Path dir = resolve(directory);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(MARKER_NAME), "");
        DecryptionSession session = new DecryptionSession(dir);
        Runtime.getRuntime().addShutdownHook(session.shutdownHook);
        return session;
    }

    /**
     * Блокирует поток до завершения приложения. Enter — штатный выход; если stdin закрыт
     * (запуск без терминала), ждём бесконечно — до сигнала завершения.
     */
    public void awaitTermination() {
        System.out.println("Расшифровка завершена. Приложение работает: для выхода нажмите Enter "
                + "или Ctrl+C — расшифрованный каталог будет безвозвратно удалён.");
        String line;
        try {
            line = ConsoleInput.readLineOrNull("");
        } catch (RuntimeException e) {
            line = null;
        }
        if (line == null) {
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public synchronized void close() {
        destroy();
        if (destroyed) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // JVM уже завершается — хук сам отработает
            }
        }
    }

    /** Идемпотентно; synchronized, чтобы хук дождался уже идущего удаления из main. */
    private synchronized void destroy() {
        if (destroyed) {
            return;
        }
        boolean deleted = false;
        for (int i = 0; i < MAX_ATTEMPTS && !deleted; i++) {
            deleted = SecureDeleter.deleteRecursively(directory);
        }
        if (deleted) {
            destroyed = true;
            System.out.println("Расшифрованные данные удалены.");
        } else {
            System.err.println("Не удалось полностью удалить расшифрованные данные. "
                    + "Повторная попытка будет при следующем запуске.");
        }
    }

    private static Path resolve(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException e) {
            return path.toAbsolutePath().normalize();
        }
    }
}
