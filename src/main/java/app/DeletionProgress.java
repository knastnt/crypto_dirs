package app;

/**
 * Однострочный индикатор прогресса удаления в консоли. Прогресс считается по объёму работы:
 * затираемые байты (два прохода) плюс фиксированный вес на каждую запись (переименование/удаление),
 * поэтому большой файл не выглядит «зависшим». Пути не выводятся.
 */
final class DeletionProgress {

    private static final long REPORT_INTERVAL_MS = 100;

    private final long totalWork;
    private final int totalEntries;
    private long doneWork;
    private int doneEntries;
    private long entryStart;
    private long entryPlanned;
    private long lastReport;
    private int lastLength;

    DeletionProgress(long totalWork, int totalEntries) {
        this.totalWork = totalWork;
        this.totalEntries = totalEntries;
    }

    void beginEntry(long plannedWork) {
        entryStart = doneWork;
        entryPlanned = plannedWork;
    }

    /** Учитывает фактически выполненную часть работы над текущей записью. */
    void advance(long work) {
        doneWork += work;
        report(false);
    }

    /** Завершает запись (успешно или нет): добирает неучтённый остаток, чтобы шкала не «отставала». */
    void endEntry() {
        doneWork = entryStart + entryPlanned;
        doneEntries++;
        report(false);
    }

    /** Печатает итоговую строку и переводит строку консоли. */
    void finish() {
        report(true);
        System.out.println();
    }

    private void report(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && now - lastReport < REPORT_INTERVAL_MS) {
            return;
        }
        lastReport = now;
        int percent = totalWork <= 0 ? 100 : (int) Math.min(100, doneWork * 100 / totalWork);
        String line = "Удаление расшифрованных данных: " + percent + "% ("
                + doneEntries + "/" + totalEntries + " объектов)";
        StringBuilder out = new StringBuilder("\r").append(line);
        for (int i = line.length(); i < lastLength; i++) {
            out.append(' '); // затираем хвост более длинной предыдущей строки
        }
        lastLength = line.length();
        System.out.print(out);
        System.out.flush();
    }
}
