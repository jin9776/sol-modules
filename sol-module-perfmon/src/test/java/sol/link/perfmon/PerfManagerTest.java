package sol.link.perfmon;

import org.junit.jupiter.api.Test;
import sol.link.perfmon.dto.engPkt.SolAppPerfDto;

public class PerfManagerTest {
    PerfManager perfManager = new PerfManager();

    @Test
    void osTest() {
        System.out.println(perfManager.collectOsPerf());
    }

    @Test
    void appTest() {
        SolAppPerfDto dto = perfManager.collectAppPerf();
        System.out.println(dto);
        System.out.println(dto.getMemUseRate());
    }
}