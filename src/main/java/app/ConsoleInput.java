package app;

import java.io.Console;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Единая точка консольного ввода. Использует {@link Console}, а при её отсутствии —
 * общий {@link java.io.BufferedReader} из {@link PasswordPrompt}, чтобы два читателя
 * System.in не «съедали» строки друг у друга.
 */
public final class ConsoleInput {

    private ConsoleInput() {
    }

    /** Читает строку; при конце потока ввода возвращает {@code null}. */
    public static String readLineOrNull(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readLine("%s", prompt);
        }
        System.out.print(prompt);
        System.out.flush();
        try {
            return PasswordPrompt.stdinReader().readLine();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Читает строку; конец потока ввода считается ошибкой (иначе циклы повторного ввода зациклились бы). */
    public static String readLine(String prompt) {
        String line = readLineOrNull(prompt);
        if (line == null) {
            throw new IllegalStateException("Ввод завершён, продолжение невозможно.");
        }
        return line.trim();
    }

    /** Запрашивает целое число в диапазоне [min, max], пока не будет введено корректное значение. */
    public static int readInt(String prompt, int min, int max) {
        while (true) {
            String line = readLine(prompt);
            try {
                int value = Integer.parseInt(line);
                if (value >= min && value <= max) {
                    return value;
                }
                System.out.println(max == Integer.MAX_VALUE
                        ? "Число должно быть не меньше " + min + "."
                        : "Число должно быть от " + min + " до " + max + ".");
            } catch (NumberFormatException e) {
                System.out.println("Введите целое число.");
            }
        }
    }

    /** Запрашивает путь (любой, существующий или нет). */
    public static Path readPath(String prompt) {
        while (true) {
            String line = readLine(prompt);
            if (line.length() >= 2 && (line.startsWith("\"") && line.endsWith("\"")
                    || line.startsWith("'") && line.endsWith("'"))) {
                line = line.substring(1, line.length() - 1).trim();
            }
            if (line.isEmpty()) {
                System.out.println("Путь не может быть пустым.");
                continue;
            }
            if (line.equals("~") || line.startsWith("~/") || line.startsWith("~\\")) {
                line = System.getProperty("user.home") + line.substring(1);
            }
            try {
                return Path.of(line).toAbsolutePath().normalize();
            } catch (InvalidPathException e) {
                System.out.println("Некорректный путь.");
            }
        }
    }

    /** Запрашивает путь к существующему каталогу. */
    public static Path readExistingDirectory(String prompt) {
        while (true) {
            Path path = readPath(prompt);
            if (Files.isDirectory(path)) {
                return path;
            }
            System.out.println("Каталог не существует.");
        }
    }
}
