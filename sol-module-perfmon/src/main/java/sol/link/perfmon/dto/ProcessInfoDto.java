package sol.link.perfmon.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ProcessInfoDto {

    private String name;
    private String args;
    private long pid;
    private long ppid;
    private double cpuLoad;
    private long memTotal;
    private long memUse;
    private int threadCnt;
    private int priority;
    private String state;
    private String user;


    public double getMemUseRate() {
        return Math.round(100d * memUse / memTotal * 100) / 100.0;
    }

}
