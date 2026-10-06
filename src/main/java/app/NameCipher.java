package app;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class NameCipher {

    private static final String TRANSFORMATION = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;
    private static final String INDEX_FILE = "vnG-zJ06hUWg2r8zAECzUmxw.tmp";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    public NameCipher(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Шифрует одно имя (файла или папки) и кодирует в Base64 URL-safe без padding.
     * Результат безопасен для использования в качестве имени в любой ФС.
     */
    public String encryptName(String name) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(name.getBytes(StandardCharsets.UTF_8));

        // Формат: IV || ciphertext
        byte[] combined = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ct, 0, combined, iv.length, ct.length);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
    }

    /**
     * Обратная операция — расшифровывает имя.
     */
    public String decryptName(String encoded) throws Exception {
        byte[] combined = Base64.getUrlDecoder().decode(encoded);
        if (combined.length < IV_LENGTH) {
            throw new IllegalArgumentException("Некорректное зашифрованное имя: " + encoded);
        }
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
        byte[] ct = new byte[combined.length - IV_LENGTH];
        System.arraycopy(combined, IV_LENGTH, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }

    /**
     * Шифрует относительный путь целиком: каждую часть (папку/файл) отдельно,
     * собирает обратно через разделитель текущей ОС.
     */
    public String encryptRelativePath(Path relative) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < relative.getNameCount(); i++) {
            if (i > 0) sb.append(File.separatorChar);
            sb.append(encryptName(relative.getName(i).toString()));
        }
        return sb.toString();
    }

    /**
     * Обратная операция для относительного пути.
     */
    public Path decryptRelativePath(String encryptedRelative) throws Exception {
        String[] parts = encryptedRelative.split(java.util.regex.Pattern.quote(File.separator));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(File.separatorChar);
            sb.append(decryptName(parts[i]));
        }
        return Path.of(sb.toString());
    }

    // ---------- Работа с индексом ----------

    /**
     * Индекс хранит соответствие: зашифрованный относительный путь -> оригинальный относительный путь.
     * Сам индекс сериализуется в текстовый формат и шифруется тем же ключом (AES-CTR + IV).
     */
    public void saveIndex(Path targetDir, Map<String, String> index) throws Exception {
        // Простой текстовый формат: одна строка на запись, разделитель TAB
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : index.entrySet()) {
            sb.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
        }

        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(sb.toString().getBytes(StandardCharsets.UTF_8));

        Path indexFile = targetDir.resolve(INDEX_FILE);
        try (OutputStream out = Files.newOutputStream(indexFile)) {
            out.write(iv);
            out.write(ct);
        }
    }

    public Map<String, String> loadIndex(Path targetDir) throws Exception {
        Path indexFile = targetDir.resolve(INDEX_FILE);
        if (!Files.exists(indexFile)) {
            return new HashMap<>();
        }

        byte[] all = Files.readAllBytes(indexFile);
        if (all.length < IV_LENGTH) {
            throw new IOException("Индекс повреждён: " + indexFile);
        }
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(all, 0, iv, 0, IV_LENGTH);
        byte[] ct = new byte[all.length - IV_LENGTH];
        System.arraycopy(all, IV_LENGTH, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] pt = cipher.doFinal(ct);

        Map<String, String> index = new HashMap<>();
        String text = new String(pt, StandardCharsets.UTF_8);
        for (String line : text.split("\n")) {
            if (line.isEmpty()) continue;
            int tab = line.indexOf('\t');
            if (tab < 0) continue;
            index.put(line.substring(0, tab), line.substring(tab + 1));
        }
        return index;
    }

    public String indexFileName() {
        return INDEX_FILE;
    }
}