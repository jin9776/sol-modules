package sol.link.perfmon.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Getter
@Setter
@ToString
@Accessors(chain = true)
public class PerfDto {

    @Setter(AccessLevel.PRIVATE)
    private double processCpuLoad;
    public double getProcessCpuLoad() {
        if (coreCnt > 0) {
            return Math.round(processCoreCpuLoad / coreCnt * 100) / 100.0;
        }
        return processCoreCpuLoad;
    }

    @Setter(AccessLevel.PRIVATE)
    private double heapUseRate;
    public double getHeapUseRate() {
        return Math.round(100d * heapUse / heapTotal * 100) / 100.0;
    }

    private double processMemUseRate;
    public double getProcessMemUseRate() {
        return Math.round(100d * processMemUseRate / memTotal * 100) / 100.0;
    }

    private double processCoreCpuLoad;
    private int coreCnt;

    private double cpuLoad;
    @Setter(AccessLevel.PRIVATE)
    private double memUseRate;
    public double getMemUseRate() {
        return Math.round(100d * memUse / memTotal * 100) / 100.0;
    }

    private long memTotal;
    private long memUse;

    private long heapTotal;
    private long heapUse;


    private int processThreadCnt;
    private long processPid;
    private String processName;
}
