package sol.link.perfmon.dto.engPkt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class SolOsPerfDto {

    private String name;
    private int engId;
    private String engTy;
    private String engIp;
    private int engPort;
    private boolean ssl;
    private int clusterId;

    private int coreCnt;
    private double cpuLoad;
    private long memTotal;
    private long memUse;
    private long swapTotal;
    private long swapUse;

    @Setter(AccessLevel.PRIVATE)
    private double memUseRate;
    @Setter(AccessLevel.PRIVATE)
    private double swapUseRate;

    public double getMemUseRate() {
        return Math.round(100d * memUse / memTotal * 100) / 100.0;
    }

    public double getSwapUseRate() {
        return Math.round(100d * swapUse / swapTotal * 100) / 100.0;
    }
}
