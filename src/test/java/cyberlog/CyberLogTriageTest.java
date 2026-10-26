package cyberlog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CyberLogTriageTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void detectsRepeatedFailuresAndSuccessAfterThem() {
        List<CyberLogTriage.Event> events = eventsForSingleUser(5);
        events.add(event(5, "alice", "192.0.2.10", CyberLogTriage.Result.SUCCESS));

        List<CyberLogTriage.Alert> alerts = CyberLogTriage.analyzeEvents(events, 5, 10);

        assertEquals(List.of("repeated-authentication-failures", "repeated-failures-then-success"),
                alerts.stream().map(CyberLogTriage.Alert::rule).toList());
    }

    @Test
    void detectsSprayAcrossDistinctAccounts() {
        List<CyberLogTriage.Event> events = new ArrayList<>();
        for (int minute = 0; minute < 5; minute++) {
            events.add(event(minute, "user" + minute, "198.51.100.8", CyberLogTriage.Result.FAILURE));
        }

        List<CyberLogTriage.Alert> alerts = CyberLogTriage.analyzeEvents(events, 5, 10);

        assertTrue(alerts.stream().anyMatch(alert -> alert.rule().equals("possible-password-spray")));
    }

    @Test
    void ignoresFailuresOutsideTheWindow() {
        List<CyberLogTriage.Event> events = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            events.add(event(index * 11, "alice", "192.0.2.10", CyberLogTriage.Result.FAILURE));
        }

        assertTrue(CyberLogTriage.analyzeEvents(events, 5, 10).isEmpty());
    }

    @Test
    void parsesQuotedCsvAndNormalizesNaiveTimestampsToUtc() throws Exception {
        Path csv = temporaryDirectory.resolve("events.csv");
        Files.writeString(csv, "\uFEFFtimestamp,username,source_ip,result\n"
                + "2026-01-01T00:00:00,\"alice, test\",192.0.2.1,FAILURE\n");

        List<CyberLogTriage.Event> events = CyberLogTriage.parseEvents(csv);

        assertEquals("alice, test", events.get(0).username());
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), events.get(0).timestamp());
        assertEquals(CyberLogTriage.Result.FAILURE, events.get(0).result());
    }

    @Test
    void rejectsInvalidIpAndThreshold() throws Exception {
        Path csv = temporaryDirectory.resolve("bad-ip.csv");
        Files.writeString(csv, "timestamp,username,source_ip,result\n"
                + "2026-01-01T00:00:00Z,alice,not-an-ip,failure\n");

        assertTrue(assertThrows(IllegalArgumentException.class, () -> CyberLogTriage.parseEvents(csv))
                .getMessage().contains("invalid IP address"));
        assertThrows(IllegalArgumentException.class, () -> CyberLogTriage.analyzeEvents(List.of(), 1, 10));
    }

    @Test
    void jsonModeReturnsAlertExitCodeAndValidLookingJson() throws Exception {
        Path csv = temporaryDirectory.resolve("events.csv");
        StringBuilder content = new StringBuilder("timestamp,username,source_ip,result\n");
        for (int minute = 0; minute < 5; minute++) {
            content.append("2026-01-01T00:0").append(minute)
                    .append(":00Z,alice,192.0.2.10,failure\n");
        }
        Files.writeString(csv, content.toString());
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int exitCode = CyberLogTriage.run(new String[]{csv.toString(), "--json"},
                new PrintStream(output, true, StandardCharsets.UTF_8), System.err);

        assertEquals(1, exitCode);
        assertFalse(output.toString(StandardCharsets.UTF_8).isBlank());
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("repeated-authentication-failures"));
    }

    private List<CyberLogTriage.Event> eventsForSingleUser(int count) {
        List<CyberLogTriage.Event> events = new ArrayList<>();
        for (int minute = 0; minute < count; minute++) {
            events.add(event(minute, "alice", "192.0.2.10", CyberLogTriage.Result.FAILURE));
        }
        return events;
    }

    private CyberLogTriage.Event event(int minute, String username, String sourceIp, CyberLogTriage.Result result) {
        return new CyberLogTriage.Event(Instant.parse("2026-01-01T00:00:00Z").plusSeconds(minute * 60L),
                username, sourceIp, result);
    }
}
