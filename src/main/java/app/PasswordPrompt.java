package app;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Запрашивает пароль у пользователя при запуске приложения.
 * В интерактивном режиме
 * по возможности используется {@link Console}, чтобы ввод не отображался.
 */
public final class PasswordPrompt {

    private static BufferedReader stdin;

    private PasswordPrompt() {
    }

    /**
     * @param confirm запросить пароль дважды (для шифрования, чтобы исключить опечатку)
     * @return введённый пароль; вызывающий код обязан затереть массив после использования
     */
    public static char[] read(boolean confirm) throws IOException {
        Console console = System.console();
        char[] password = readSecret(console, "Введите пароль: ");
        if (password == null || password.length == 0) {
            throw new IllegalStateException("Пароль не может быть пустым.");
        }

        if (confirm) {
            char[] repeated = readSecret(console, "Повторите пароль: ");
            boolean matches = repeated != null && Arrays.equals(password, repeated);
            if (repeated != null) {
                Arrays.fill(repeated, '\0');
            }
            if (!matches) {
                Arrays.fill(password, '\0');
                throw new IllegalStateException("Пароли не совпадают.");
            }
        }
        return password;
    }

    private static char[] readSecret(Console console, String prompt) throws IOException {
        if (console != null) {
            return console.readPassword(prompt);
        }
        if (System.in == null) {
            return null;
        }
        System.out.print(prompt);
        System.out.flush();
        String line = stdinReader().readLine();
        return line == null ? null : line.toCharArray();
    }

    // Один общий reader на процесс: BufferedReader читает вперёд и иначе «съедал» бы
    // следующую строку при повторном запросе пароля (подтверждение).
    static BufferedReader stdinReader() {
        if (stdin == null) {
            stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        }
        return stdin;
    }
}
