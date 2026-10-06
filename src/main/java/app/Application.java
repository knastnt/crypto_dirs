package app;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class Application {

    public static void main(String[] args) {
        try {
            runMainMenu();
        } catch (Exception e) {
            System.err.println("Ошибка: " + e.getMessage());
            System.exit(1);
        }
    }

    // ---------- Меню ----------

    private static void runMainMenu() throws Exception {
        System.out.println("1 - Зашифровать каталог");
        System.out.println("2 - Расшифровать каталог");
        System.out.println("3 - Расшифровать каталог с последующим безопасным удалением расшифрованных файлов");

        int choice = ConsoleInput.readInt("Выберите режим (1-3): ", 1, 3);
        switch (choice) {
            case 1:
                encryptDirectory();
                break;
            case 2:
                decryptDirectory();
                break;
            default:
                decryptDirectoryAndWipeOnExit();
                break;
        }
    }

    // ---------- Режим 1 ----------

    private static void encryptDirectory() throws Exception {
        Path source = ConsoleInput.readExistingDirectory("Путь к исходной директории: ");
        Path target = readEncryptionTarget(source);
        CryptoRunner.run(Mode.ENCRYPT, source, target);
    }

    /** Целевой каталог не должен совпадать с исходным или лежать внутри него (иначе обход зациклится на результатах). */
    private static Path readEncryptionTarget(Path source) {
        while (true) {
            Path target = ConsoleInput.readPath("Путь к целевой директории: ");
            if (target.startsWith(source)) {
                System.out.println("Целевая директория не должна совпадать с исходной или находиться внутри неё.");
                continue;
            }
            return target;
        }
    }

    // ---------- Режим 2 ----------

    private static void decryptDirectory() throws Exception {
        PathPair dirs = chooseDecryptionDirectories(false);
        CryptoRunner.run(Mode.DECRYPT, dirs.source(), dirs.target());
    }

    // ---------- Режим 3 ----------

    /**
     * Расшифровывает, затем ждёт завершения работы; при любом выходе каталог расшифровки
     * удаляется (см. {@link DecryptionSession}).
     */
    private static void decryptDirectoryAndWipeOnExit() throws Exception {
        PathPair dirs = chooseDecryptionDirectories(true);
        try (DecryptionSession session = DecryptionSession.open(dirs.target())) {
            CryptoRunner.run(Mode.DECRYPT, dirs.source(), dirs.target());
            session.awaitTermination();
        }
    }

    // ---------- Общее для режимов 2 и 3 ----------

    /**
     * @param wipeTarget {@code true} для режима 3: каталог расшифровки будет удалён целиком,
     *                   поэтому он дополнительно проверяется ({@link DecryptionSession#checkTarget})
     */
    private static PathPair chooseDecryptionDirectories(boolean wipeTarget) {
        System.out.println("1 - Ввести путь к зашифрованному каталогу");
        System.out.println("2 - Выбрать предустановленный путь");
        int variant = ConsoleInput.readInt("Ваш выбор (1-2): ", 1, 2);
        return variant == 1 ? readManualDirectories(wipeTarget) : choosePredefinedDirectories(wipeTarget);
    }

    /** Источник и цель всегда запрашиваются явно. */
    private static PathPair readManualDirectories(boolean wipeTarget) {
        Path source = ConsoleInput.readExistingDirectory("Путь к зашифрованному каталогу: ");
        while (true) {
            Path target = ConsoleInput.readPath(wipeTarget
                    ? "Путь для расшифрованных файлов (будет удалён при завершении): "
                    : "Путь для расшифрованных файлов: ");
            Optional<String> error = wipeTarget
                    ? DecryptionSession.checkTarget(source, target)
                    : Optional.empty();
            if (error.isEmpty()) {
                return new PathPair(source, target);
            }
            System.out.println(error.get());
        }
    }

    /** Пути не печатаются: пользователь вводит только номер. */
    private static PathPair choosePredefinedDirectories(boolean wipeTarget) {
        while (true) {
            int number = ConsoleInput.readInt("Введите номер каталога: ", 1, Integer.MAX_VALUE);
            Optional<PathPair> pair = PredefinedPaths.find(number);
            if (pair.isEmpty()) {
                System.out.println("Каталога с таким номером не существует.");
                continue;
            }
            if (!Files.isDirectory(pair.get().source())) {
                System.out.println("Выбранный каталог недоступен.");
                continue;
            }
            Optional<String> error = wipeTarget
                    ? DecryptionSession.checkTarget(pair.get().source(), pair.get().target())
                    : Optional.empty();
            if (error.isPresent()) {
                System.out.println(error.get());
                continue;
            }
            return pair.get();
        }
    }
}
