package sol.link.perfmon.dto.engPkt;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SolAppPerfDto {

    private String name;
    private int engId;
    private String engTy;
    private String engIp;
    private int engPort;
    private boolean ssl;
    private int clusterId;

    private int pid;
    private double cpuLoad;

    private long memTotal;
    private long memUse;
    private int threadCnt;

    @Setter(AccessLevel.PRIVATE)
    private double memUseRate;
    public double getMemUseRate() {
        return Math.round(100d * memUse / memTotal * 100) / 100.0;
    }
}
