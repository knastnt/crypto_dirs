package app;

import java.nio.file.Path;

/** Пара «исходный (зашифрованный) каталог — целевой (расшифрованный) каталог». */
public record PathPair(Path source, Path target) {
}
