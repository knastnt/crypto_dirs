package app;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

/**
 * Захардкоженные пары путей: зашифрованный каталог -> каталог для расшифрованных данных.
 * Сами пути нигде не выводятся — пользователь оперирует только номерами.
 */
public final class PredefinedPaths {

    private static final Map<Integer, PathPair> PATHS = Map.of(
            1, new PathPair(Path.of("/home/user/0"), Path.of("/home/user/0+"))
    );

    private PredefinedPaths() {
    }

    public static Optional<PathPair> find(int number) {
        return Optional.ofNullable(PATHS.get(number));
    }
}
