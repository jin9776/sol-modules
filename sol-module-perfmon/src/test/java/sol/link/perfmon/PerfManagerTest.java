package sol.link.perfmon;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

public class PerfManagerTest {
    PerfManager perfManager = PerfManager.getInstance();

    @Test
    void perf() throws InterruptedException {

        Instant startTime = Instant.now();

        var dto = perfManager.getPerf();
        System.out.println(dto);
        System.out.println(Duration.between(startTime, Instant.now()).getSeconds());

        Thread.sleep(2000);

        dto = perfManager.getPerf();
        System.out.println(dto);
        System.out.println(Duration.between(startTime, Instant.now()).getSeconds() );

        Thread.sleep(2000);

        dto = perfManager.getPerf();
        System.out.println(dto);
        System.out.println(Duration.between(startTime, Instant.now()).getSeconds() );
    }
}