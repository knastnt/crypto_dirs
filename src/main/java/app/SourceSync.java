package app;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Перенос изменений из расшифрованного каталога обратно в зашифрованный (режим 4).
 * Пути в сообщениях не выводятся.
 */
final class SourceSync {

    enum Outcome { SKIPPED, SYNCED }

    record FileState(long size, long mtimeNanos) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private SourceSync() {
    }

    /** Слепок обычных файлов каталога (симлинки не разыменовываются, маркер исключён). */
    static Map<String, FileState> snapshot(Path dir) throws IOException {
        Map<String, FileState> map = new HashMap<>();
        Files.walkFileTree(dir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile()) {
                    String rel = dir.relativize(file).toString();
                    if (!rel.equals(DecryptionSession.MARKER_NAME)) {
                        map.put(rel, new FileState(attrs.size(),
                                attrs.lastModifiedTime().to(TimeUnit.NANOSECONDS)));
                    }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        return map;
    }

    /**
     * @return SKIPPED, если синхронизировать нечего или каталог расшифровки выглядит утраченным;
     *         SYNCED при успехе. При ошибке бросает исключение, а source остаётся прежним.
     */
    static Outcome apply(Path source, Path plain, Map<String, FileState> baseline, byte[] key)
            throws Exception {
        if (!Files.isDirectory(plain, LinkOption.NOFOLLOW_LINKS)) {
            return Outcome.SKIPPED;
        }
        Map<String, FileState> now = snapshot(plain);
        // Ни одного файла из слепка не осталось: каталог пуст/подменён/не смонтирован.
        if (baseline.keySet().stream().noneMatch(now::containsKey)) {
            return Outcome.SKIPPED;
        }

        NameCipher nameCipher = new NameCipher(key);
        Map<String, String> index = nameCipher.loadIndex(source);       // enc -> orig
        if (index.isEmpty()) {
            throw new IllegalStateException("Индекс пуст.");
        }
        Map<String, String> byOrig = new HashMap<>();
        index.forEach((enc, orig) -> byOrig.put(orig, enc));

        Set<String> skipEnc = new HashSet<>();                          // не переносить из старого source
        Map<String, String> toEncrypt = new LinkedHashMap<>();          // rel -> enc
        int added = 0, modified = 0, deleted = 0;

        for (Map.Entry<String, FileState> e : now.entrySet()) {
            String rel = e.getKey();
            FileState before = baseline.get(rel);
            if (before != null && before.equals(e.getValue())) {
                continue;
            }
            String enc = byOrig.get(rel);
            if (enc != null) {
                skipEnc.add(enc);
                modified++;
            } else {
                enc = nameCipher.encryptRelativePath(Path.of(rel)) + FileEncryptor.ENC_EXT;
                index.put(enc, rel);
                added++;
            }
            toEncrypt.put(rel, enc);
        }
        for (String rel : baseline.keySet()) {
            if (now.containsKey(rel)) {
                continue;
            }
            String enc = byOrig.get(rel);
            if (enc != null) {
                skipEnc.add(enc);
                index.remove(enc);
            }
            deleted++;
        }

        if (added + modified + deleted == 0) {
            return Outcome.SYNCED;
        }
        System.out.println("Изменения: добавлено " + added + ", изменено " + modified
                + ", удалено " + deleted + ".");

        Path backup = uniqueSibling(source);
        Files.move(source, backup);                                     // если не вышло — ничего не изменено
        boolean success = false;
        try {
            Files.createDirectories(source);
            carryOver(backup, source, skipEnc, nameCipher.indexFileName());
            for (Map.Entry<String, String> e : toEncrypt.entrySet()) {
                FileEncryptor.encryptFile(plain.resolve(e.getKey()), source.resolve(e.getValue()),
                        key, new Properties());                         // новый IV на каждый вызов
            }
            nameCipher.saveIndex(source, index);
            success = true;
        } finally {
            if (!success) {
                deleteTree(source);
                try {
                    Files.move(backup, source);
                } catch (IOException ex) {
                    System.err.println("Не удалось вернуть исходный зашифрованный каталог: "
                            + "он сохранён рядом под временным именем (*.sync-*).");
                }
            }
        }
        if (!deleteTree(backup)) {
            System.err.println("Не удалось полностью удалить старую копию зашифрованного каталога "
                    + "(*.sync-*); её можно удалить вручную.");
        }
        return Outcome.SYNCED;
    }

    /** Переносит файлы старого source в новый: жёсткая ссылка, при невозможности — копия. */
    private static void carryOver(Path from, Path to, Set<String> skipEnc, String indexName)
            throws IOException {
        Files.walkFileTree(from, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                String rel = from.relativize(file).toString();
                if (rel.equals(indexName) || skipEnc.contains(rel)) {
                    return FileVisitResult.CONTINUE;
                }
                Path target = to.resolve(rel);
                Files.createDirectories(target.getParent());            // пустые папки не переносим
                try {
                    Files.createLink(target, file);
                } catch (IOException | UnsupportedOperationException e) {
                    Files.copy(file, target, StandardCopyOption.COPY_ATTRIBUTES);
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static Path uniqueSibling(Path source) throws IOException {
        Path name = source.getFileName();
        if (name == null) {
            throw new IOException("Нельзя переименовать корневой каталог.");
        }
        for (int i = 0; i < 10; i++) {
            byte[] b = new byte[6];
            RANDOM.nextBytes(b);
            Path candidate = source.resolveSibling(name + ".sync-" + HexFormat.of().formatHex(b));
            if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
                return candidate;
            }
        }
        throw new IOException("Не удалось подобрать временное имя.");
    }

    /** Обычное удаление (НЕ SecureDeleter: файлы могут делить inode с новым source). */
    private static boolean deleteTree(Path root) {
        boolean[] ok = {true};
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    try {
                        Files.deleteIfExists(file);
                    } catch (IOException e) {
                        ok[0] = false;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    ok[0] = false;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                    try {
                        Files.deleteIfExists(dir);
                    } catch (IOException e) {
                        ok[0] = false;
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            ok[0] = false;
        }
        return ok[0];
    }
}