package cyberlog;

import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class CyberLogTriage {
    private static final Set<String> REQUIRED_COLUMNS = Set.of("timestamp", "username", "source_ip", "result");
    private static final ObjectMapper JSON = new ObjectMapper();

    private CyberLogTriage() {
    }

    public enum Result {
        SUCCESS,
        FAILURE
    }

    public record Event(Instant timestamp, String username, String sourceIp, Result result) {
    }

    public record Alert(
            String severity,
            String rule,
            String sourceIp,
            Instant timestamp,
            String description,
            String username) {
    }

    public static List<Event> parseEvents(Path path) throws IOException {
        List<Event> events = new ArrayList<>();
        try (Reader reader = Files.newBufferedReader(path);
                CSVParser parser = CSVFormat.DEFAULT.builder()
                        .setHeader()
                        .setSkipHeaderRecord(true)
                        .get()
                        .parse(reader)) {
            List<String> headers = new ArrayList<>(parser.getHeaderNames());
            if (!headers.isEmpty()) {
                headers.set(0, headers.get(0).replace("\uFEFF", ""));
            }
            Map<String, Integer> columns = new HashMap<>();
            for (int index = 0; index < headers.size(); index++) {
                String name = headers.get(index).trim().toLowerCase(Locale.ROOT);
                if (columns.put(name, index) != null) {
                    throw new IllegalArgumentException("CSV contains duplicate column names");
                }
            }
            if (!columns.keySet().containsAll(REQUIRED_COLUMNS)) {
                Set<String> missing = new HashSet<>(REQUIRED_COLUMNS);
                missing.removeAll(columns.keySet());
                throw new IllegalArgumentException("missing required CSV columns: " + String.join(", ", missing));
            }

            for (CSVRecord row : parser) {
                int rowNumber = (int) row.getRecordNumber() + 1;
                if (!row.isConsistent()) {
                    throw new IllegalArgumentException("row " + rowNumber + ": malformed CSV row");
                }
                String username = row.get(columns.get("username")).trim();
                String sourceIp = normalizeIp(row.get(columns.get("source_ip")).trim(), rowNumber);
                String resultValue = row.get(columns.get("result")).trim().toLowerCase(Locale.ROOT);
                if (username.isEmpty()) {
                    throw new IllegalArgumentException("row " + rowNumber + ": username cannot be empty");
                }
                Result result = switch (resultValue) {
                    case "success" -> Result.SUCCESS;
                    case "failure" -> Result.FAILURE;
                    default -> throw new IllegalArgumentException(
                            "row " + rowNumber + ": result must be success or failure");
                };
                events.add(new Event(parseTimestamp(row.get(columns.get("timestamp")), rowNumber),
                        username, sourceIp, result));
            }
        }
        events.sort(Comparator.comparing(Event::timestamp));
        return events;
    }

    private static Instant parseTimestamp(String value, int rowNumber) {
        String trimmed = value.trim();
        try {
            return OffsetDateTime.parse(trimmed).toInstant();
        } catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(trimmed).toInstant(ZoneOffset.UTC);
            } catch (DateTimeParseException exception) {
                throw new IllegalArgumentException("row " + rowNumber + ": invalid ISO-8601 timestamp", exception);
            }
        }
    }

    private static String normalizeIp(String value, int rowNumber) {
        try {
            if (value.indexOf(':') < 0) {
                String[] octets = value.split("\\.", -1);
                if (octets.length != 4) {
                    throw new UnknownHostException();
                }
                for (String octet : octets) {
                    if (!octet.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octet) > 255) {
                        throw new UnknownHostException();
                    }
                }
                return String.join(".", octets);
            }
            if (!value.matches("[0-9a-fA-F:.]+")) {
                throw new UnknownHostException();
            }
            return InetAddress.getByName(value).getHostAddress();
        } catch (UnknownHostException | NumberFormatException exception) {
            throw new IllegalArgumentException("row " + rowNumber + ": invalid IP address", exception);
        }
    }

    public static List<Alert> analyzeEvents(List<Event> events, int threshold, int windowMinutes) {
        if (threshold < 2) {
            throw new IllegalArgumentException("threshold must be at least 2");
        }
        if (windowMinutes < 1) {
            throw new IllegalArgumentException("window_minutes must be at least 1");
        }

        Duration window = Duration.ofMinutes(windowMinutes);
        Map<String, List<Event>> eventsByIp = new LinkedHashMap<>();
        for (Event event : events) {
            eventsByIp.computeIfAbsent(event.sourceIp(), ignored -> new ArrayList<>()).add(event);
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<Event>> entry : eventsByIp.entrySet()) {
            String sourceIp = entry.getKey();
            List<Event> sourceEvents = entry.getValue();
            sourceEvents.sort(Comparator.comparing(Event::timestamp));
            Deque<Event> failures = new ArrayDeque<>();
            Map<String, Integer> failuresByUser = new HashMap<>();
            Set<String> reportedBruteForce = new HashSet<>();
            Set<String> reportedSuccess = new HashSet<>();
            boolean reportedSpray = false;

            for (Event event : sourceEvents) {
                while (!failures.isEmpty()
                        && Duration.between(failures.peekFirst().timestamp(), event.timestamp()).compareTo(window) > 0) {
                    Event expired = failures.removeFirst();
                    failuresByUser.computeIfPresent(expired.username(),
                            (username, count) -> count == 1 ? null : count - 1);
                }
                reportedBruteForce.removeIf(username -> failuresByUser.getOrDefault(username, 0) < threshold);
                reportedSuccess.removeIf(username -> failuresByUser.getOrDefault(username, 0) < threshold);
                if (failuresByUser.size() < threshold) {
                    reportedSpray = false;
                }

                if (event.result() == Result.SUCCESS) {
                    int userFailures = failuresByUser.getOrDefault(event.username(), 0);
                    if (userFailures >= threshold && reportedSuccess.add(event.username())) {
                        alerts.add(new Alert("high", "repeated-failures-then-success", sourceIp,
                                event.timestamp(), "Successful login followed " + userFailures
                                + " failed attempts within the configured window.", event.username()));
                    }
                    continue;
                }

                failures.addLast(event);
                int userFailures = failuresByUser.merge(event.username(), 1, Integer::sum);
                if (userFailures >= threshold && reportedBruteForce.add(event.username())) {
                    alerts.add(new Alert("high", "repeated-authentication-failures", sourceIp,
                            event.timestamp(), "At least " + threshold + " failed logins for this account occurred "
                            + "within " + windowMinutes + " minutes.", event.username()));
                }
                if (failuresByUser.size() >= threshold && !reportedSpray) {
                    alerts.add(new Alert("medium", "possible-password-spray", sourceIp, event.timestamp(),
                            "Failed logins targeted " + failuresByUser.size() + " distinct accounts within "
                            + windowMinutes + " minutes.", null));
                    reportedSpray = true;
                }
            }
        }
        alerts.sort(Comparator.comparing(Alert::timestamp));
        return alerts;
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        Path csvPath = null;
        int threshold = 5;
        int windowMinutes = 10;
        boolean json = false;
        try {
            for (int index = 0; index < args.length; index++) {
                switch (args[index]) {
                    case "--threshold" -> threshold = Integer.parseInt(args[++index]);
                    case "--window" -> windowMinutes = Integer.parseInt(args[++index]);
                    case "--json" -> json = true;
                    default -> {
                        if (args[index].startsWith("--")) {
                            throw new IllegalArgumentException("unknown option: " + args[index]);
                        }
                        if (csvPath != null) {
                            throw new IllegalArgumentException("provide only one CSV file");
                        }
                        csvPath = Path.of(args[index]);
                    }
                }
            }
            if (csvPath == null) {
                throw new IllegalArgumentException("usage: cyberlog <csv_file> [--threshold N] [--window MINUTES] [--json]");
            }
            List<Alert> alerts = analyzeEvents(parseEvents(csvPath), threshold, windowMinutes);
            if (json) {
                printJson(alerts, out);
            } else if (alerts.isEmpty()) {
                out.println("No matching authentication patterns found.");
            } else {
                out.println("Found " + alerts.size() + " alert(s):");
                for (Alert alert : alerts) {
                    String account = alert.username() == null ? "" : " | user=" + alert.username();
                    out.println("[" + alert.severity().toUpperCase(Locale.ROOT) + "] " + alert.rule()
                            + " | " + alert.timestamp() + " | source=" + alert.sourceIp() + account);
                    out.println("  " + alert.description());
                }
            }
            return alerts.isEmpty() ? 0 : 1;
        } catch (IOException | IllegalArgumentException | IndexOutOfBoundsException exception) {
            err.println("error: " + exception.getMessage());
            return 2;
        }
    }

    private static void printJson(List<Alert> alerts, PrintStream out) throws IOException {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Alert alert : alerts) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("severity", alert.severity());
            row.put("rule", alert.rule());
            row.put("source_ip", alert.sourceIp());
            row.put("timestamp", alert.timestamp().toString());
            row.put("description", alert.description());
            row.put("username", alert.username());
            rows.add(row);
        }
        out.println(JSON.writeValueAsString(rows));
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }
}
