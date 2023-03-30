package sol.link.perfmon;

import lombok.Getter;
import lombok.Setter;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.software.os.OSProcess;
import oshi.util.Util;
import sol.link.perfmon.dto.ProcessInfoDto;
import sol.link.perfmon.dto.engPkt.SolAppPerfDto;
import sol.link.perfmon.dto.engPkt.SolOsPerfDto;

@Getter
@Setter
public class PerfManager {

    private final int DEFAULT_SLEEP = 1000;

    private SystemInfo systemInfo = new SystemInfo();

    public SolOsPerfDto collectOsPerf() {
        return collectOsPerf(DEFAULT_SLEEP);
    }
    public SolOsPerfDto collectOsPerf(int sleep) {
        SolOsPerfDto dto = new SolOsPerfDto();
        getSystemCpu(systemInfo.getHardware().getProcessor(), dto, sleep);
        getSystemMem(systemInfo.getHardware().getMemory(), dto);
        dto.setCoreCnt(Runtime.getRuntime().availableProcessors());
        return dto;
    }

    /**
     * Application 성능을 수집한다.
     */
    public SolAppPerfDto collectAppPerf() {
        SolAppPerfDto dto = new SolAppPerfDto();

        int pid = getProcessId();
        OSProcess curProcess = getProcess(pid);
        if (curProcess != null) {
            dto.setName(curProcess.getName());
            dto.setPid(pid);
            dto.setCpuLoad(Math.round(100d * (curProcess.getKernelTime() + curProcess.getUserTime()) / curProcess.getUpTime() * 10) / 10.0);
            dto.setMemTotal(systemInfo.getHardware().getMemory().getTotal());
            dto.setMemUse(curProcess.getResidentSetSize());
            dto.setThreadCnt(curProcess.getThreadCount());
        }

        return dto;
    }

    /**
     * 프로세스 정보르 가져온다.
     */
    public ProcessInfoDto collectProcess(int pid) {
        OSProcess process = getProcess(pid);

        if (process == null) {
            return null;
        }

        ProcessInfoDto dto = new ProcessInfoDto();
        dto.setName(process.getName());
        dto.setPid(pid);
        dto.setCpuLoad(100d * (process.getKernelTime() + process.getUserTime()) / process.getUpTime());
        dto.setMemTotal(systemInfo.getHardware().getMemory().getTotal());
        dto.setMemUse(process.getResidentSetSize());
        dto.setThreadCnt(process.getThreadCount());
        dto.setPpid(process.getParentProcessID());
        dto.setPriority(process.getPriority());
        dto.setState(process.getState().toString());
        dto.setUser(process.getUser());

        StringBuilder sb = new StringBuilder();
        for(String s : process.getArguments()) {
            sb.append(s).append(" ");
        }
        dto.setArgs(sb.toString().trim());

        return dto;
    }

    /**
     * 현재 Application 의 PID 를 가져온다.
     */
    public int getProcessId() {
        return systemInfo.getOperatingSystem().getProcessId();
    }

    /**
     * OS 의 CPU 를 가져온다.
     * @param sleep millisecond (ms)
     */
    private void getSystemCpu(CentralProcessor processor, SolOsPerfDto solOsPerfDto, int sleep) {
        long[] prevTicks = processor.getSystemCpuLoadTicks();
        Util.sleep(sleep);
        // long[] ticks = processor.getSystemCpuLoadTicks();

        solOsPerfDto.setCpuLoad(Math.round(processor.getSystemCpuLoadBetweenTicks(prevTicks) * 100 * 100) / 100.0); // digit 2
    }
    private void getSystemCpu(CentralProcessor processor, SolOsPerfDto solOsPerfDto) {
        getSystemCpu(processor, solOsPerfDto, DEFAULT_SLEEP);
    }

    /**
     * OS 의 Memory 를 가져온다.
     */
    private void getSystemMem(GlobalMemory memory, SolOsPerfDto solOsPerfDto) {
        solOsPerfDto.setMemTotal(memory.getTotal());
        solOsPerfDto.setMemUse(memory.getTotal() - memory.getAvailable());

        switch (SystemInfo.getCurrentPlatform()) {
            case WINDOWS:
            case WINDOWSCE:
                solOsPerfDto.setSwapTotal(memory.getVirtualMemory().getVirtualMax());
                solOsPerfDto.setSwapUse(memory.getVirtualMemory().getVirtualInUse());
                break;
            default:
                solOsPerfDto.setSwapTotal(memory.getVirtualMemory().getSwapTotal());
                solOsPerfDto.setSwapUse(memory.getVirtualMemory().getSwapUsed());
                break;
        }
    }

    private OSProcess getProcess(int pid) {
        return systemInfo.getOperatingSystem().getProcess(pid);
    }
}
