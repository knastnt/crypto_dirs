package app;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Необратимое удаление каталога: содержимое файлов затирается (случайные данные, затем нули),
 * файл усекается, переименовывается в случайное имя (чтобы не осталось исходного имени) и удаляется.
 * Симлинки не разыменовываются — удаляется только сама ссылка.
 *
 * <p><b>Ограничения:</b> на SSD (wear leveling), в CoW/журналируемых ФС (btrfs, ZFS, APFS) и
 * при снапшотах/бэкапах гарантировать физическое затирание невозможно — для этого нужно
 * полнодисковое шифрование. На Windows файл, открытый без FILE_SHARE_DELETE, удалить нельзя;
 * в этом случае метод вернёт {@code false}, а повтор будет выполнен при следующем запуске.
 */
public final class SecureDeleter {

    private static final int BUFFER_SIZE = 64 * 1024;
    private static final int MAX_ATTEMPTS = 3;
    private static final int RETRY_PAUSE_MS = 200;
    /** Вес записи (переименование + удаление) в единицах прогресса — как у 64 КБ данных. */
    private static final long ENTRY_WEIGHT = BUFFER_SIZE;

    /** Запись дерева и её размер (для расчёта прогресса). */
    private record Entry(Path path, long size) {
        long plannedWork() {
            return 2 * size + ENTRY_WEIGHT; // два прохода затирания + служебные операции
        }
    }

    private SecureDeleter() {
    }

    /**
     * Удаляет каталог, отображая прогресс в консоли.
     *
     * @return {@code true}, если каталог (или файл) больше не существует
     */
    public static boolean deleteRecursively(Path root) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            if (!exists(root)) {
                return true;
            }
            if (attempt > 1) {
                System.out.println("Часть данных не удалена, повторная попытка " + attempt
                        + "/" + MAX_ATTEMPTS + "...");
            }
            List<Entry> entries = collect(root);
            long totalWork = entries.stream().mapToLong(Entry::plannedWork).sum();
            DeletionProgress progress = new DeletionProgress(totalWork, entries.size());
            for (Entry entry : entries) {
                progress.beginEntry(entry.plannedWork());
                try {
                    destroyEntry(entry.path(), progress);
                } catch (IOException | RuntimeException ignored) {
                    // продолжаем с остальными; итог определяется проверкой существования ниже
                } finally {
                    progress.endEntry();
                }
            }
            progress.finish();
            if (!exists(root)) {
                return true;
            }
            pause();
        }
        return !exists(root);
    }

    /** Собирает все записи так, чтобы потомки шли раньше родителей. */
    private static List<Entry> collect(Path root) {
        List<Entry> entries = new ArrayList<>();
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    makeAccessible(dir, true);
                    entries.add(new Entry(dir, 0));
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    entries.add(new Entry(file, attrs.isRegularFile() ? attrs.size() : 0));
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    entries.add(new Entry(file, 0));
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ignored) {
            // собрали сколько смогли
        }
        Collections.reverse(entries); // обход pre-order -> разворот даёт «сначала вложенные»
        return entries;
    }

    private static void destroyEntry(Path path, DeletionProgress progress) throws IOException {
        if (!exists(path)) {
            return;
        }
        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (attrs.isRegularFile()) {
            makeAccessible(path, false);
            try {
                overwrite(path, progress);
            } catch (IOException ignored) {
                // не смогли затереть (блокировка/права) — всё равно пробуем удалить
            }
        } else if (attrs.isDirectory()) {
            makeAccessible(path, true);
        }
        removeEntry(path);
    }

    private static void overwrite(Path file, DeletionProgress progress) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            long size = channel.size();
            writePass(channel, size, true, progress);
            writePass(channel, size, false, progress);
            channel.truncate(0);
            channel.force(true);
        }
    }

    private static void writePass(FileChannel channel, long size, boolean random,
                                  DeletionProgress progress) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        long position = 0;
        while (position < size) {
            int chunk = (int) Math.min(BUFFER_SIZE, size - position);
            buffer.clear();
            if (random) {
                ThreadLocalRandom.current().nextBytes(buffer.array());
            }
            buffer.limit(chunk);
            while (buffer.hasRemaining()) {
                int written = channel.write(buffer, position);
                position += written;
                progress.advance(written);
            }
        }
        channel.force(true);
    }

    /** Переименовывает запись в случайное имя и удаляет её (с повторами и снятием read-only). */
    private static void removeEntry(Path path) throws IOException {
        Path target = path;
        try {
            Path renamed = path.resolveSibling(randomName());
            Files.move(path, renamed);
            target = renamed;
        } catch (IOException ignored) {
            // удалим под исходным именем
        }

        IOException last = null;
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            try {
                Files.deleteIfExists(target);
                return;
            } catch (IOException e) {
                last = e;
                makeAccessible(target, Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS));
                pause();
            }
        }
        throw last;
    }

    private static void makeAccessible(Path path, boolean directory) {
        try {
            Files.setAttribute(path, "dos:readonly", false, LinkOption.NOFOLLOW_LINKS);
        } catch (Exception ignored) {
            // не Windows
        }
        try {
            Set<PosixFilePermission> perms =
                    Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            if (directory) {
                perms.add(PosixFilePermission.OWNER_EXECUTE);
            }
            Files.setPosixFilePermissions(path, perms);
        } catch (Exception ignored) {
            // не POSIX или симлинк
        }
    }

    private static String randomName() {
        byte[] bytes = new byte[12];
        ThreadLocalRandom.current().nextBytes(bytes);
        return "." + HexFormat.of().formatHex(bytes);
    }

    private static boolean exists(Path path) {
        return Files.exists(path, LinkOption.NOFOLLOW_LINKS);
    }

    private static void pause() {
        try {
            Thread.sleep(RETRY_PAUSE_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
