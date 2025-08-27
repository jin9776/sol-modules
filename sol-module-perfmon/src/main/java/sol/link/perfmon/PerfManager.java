package sol.link.perfmon;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import oshi.SystemInfo;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.software.os.OSProcess;
import oshi.util.Util;
import sol.link.perfmon.dto.PerfDto;
import sol.link.perfmon.dto.ProcessInfoDto;

import java.lang.management.OperatingSystemMXBean;

@Getter
@Setter
@Slf4j
public class PerfManager {

    private static final PerfManager INSTANCE = new PerfManager();
    public static PerfManager getInstance() {
        return INSTANCE;
    }
    private PerfManager() {}

    private static final double PERCENT = 100d;

    private final SystemInfo systemInfo = new SystemInfo();
    private final oshi.hardware.HardwareAbstractionLayer hal = systemInfo.getHardware();
    private final CentralProcessor processor = hal.getProcessor();
    private final GlobalMemory memory = hal.getMemory();
    private OSProcess curProcess;

    private long pid;
    private boolean osBeanChecked = false; // OS Bean 수집 방식 체크 여부
    private com.sun.management.OperatingSystemMXBean sunOsBean = null;

    public PerfDto getPerf() {
        PerfDto dto = new PerfDto();

        // OS 수집
        if (!osBeanChecked && sunOsBean == null) {
            collectOs(dto);
        } else {
            collectOsFromOshi(dto);
        }

        // JVM Heap 수집
        collectHeap(dto);

        // Process 수집
        collectAppWithOshi(dto);
        return dto;
    }


    private void collectOs(PerfDto dto) {
        initSunOsBean();
        if (sunOsBean != null) {
            dto.setCpuLoad(toPercent(sunOsBean.getCpuLoad()));
            dto.setMemTotal(sunOsBean.getTotalMemorySize());
            dto.setMemUse(dto.getMemTotal() - sunOsBean.getFreeMemorySize());
            dto.setCoreCnt(sunOsBean.getAvailableProcessors());
        }
    }

    /**
     * JVM Heap 수집
     */
    private void collectHeap(PerfDto dto) {
        try {
            Runtime runtime = Runtime.getRuntime();
            dto.setHeapTotal(runtime.totalMemory());
            dto.setHeapUse(dto.getHeapTotal() - runtime.freeMemory());
        } catch (Exception e) {
            log.warn("fail to collect heap : {}", e.getMessage(), e);
        }
    }

    /**
     * OSHI 에서 OS 정보 수집
     */
    private void collectOsFromOshi(PerfDto dto) {
        fillSystemCpu(this.processor, dto);
        fillSystemMem(this.memory, dto);
        dto.setCoreCnt(Runtime.getRuntime().availableProcessors());
    }

    /**
     * Application 성능을 수집한다.
     */
    private void collectAppWithOshi(PerfDto dto) {
        if (this.curProcess == null) {
            long pid = getProcessId();
            this.curProcess = findProcess(pid);
        }

        if (curProcess != null) {
            dto.setProcessName(curProcess.getName());
            dto.setProcessPid(pid);

            initSunOsBean();
            if (sunOsBean != null) {
                dto.setProcessCoreCpuLoad(toPercent(sunOsBean.getProcessCpuLoad()));
            } else {
                double ratio = (double) (curProcess.getKernelTime() + curProcess.getUserTime()) / Math.max(1L, curProcess.getUpTime());
                dto.setProcessCoreCpuLoad(roundTo(ratio * PERCENT, 1));
                //dto.setProcessCoreCpuLoad(Math.round(100d * (curProcess.getKernelTime() + curProcess.getUserTime()) / curProcess.getUpTime() * 10) / 10.0);
            }

            dto.setProcessMemUseRate(curProcess.getResidentSetSize());
            dto.setProcessThreadCnt(curProcess.getThreadCount());
        }
    }

    /**
     * 프로세스 정보르 가져온다.
     */
    public ProcessInfoDto getProcess(long pid) {
        OSProcess process = findProcess(pid);

        if (process == null) {
            return null;
        }

        ProcessInfoDto dto = new ProcessInfoDto();
        dto.setName(process.getName());
        dto.setPid(pid);
        dto.setCpuLoad(PERCENT * (process.getKernelTime() + process.getUserTime()) / Math.max(1L, process.getUpTime()));
        dto.setMemTotal(this.memory.getTotal());
        dto.setMemUse(process.getResidentSetSize());
        dto.setThreadCnt(process.getThreadCount());
        dto.setPpid(process.getParentProcessID());
        dto.setPriority(process.getPriority());
        dto.setState(process.getState().toString());
        dto.setUser(process.getUser());

        dto.setArgs(String.join(" ", process.getArguments()));

        return dto;
    }

    /**
     * 현재 Application 의 PID 를 가져온다.
     */
    public long getProcessId() {
        if (pid > 0) { return pid; }

        // # 1. runtime
        ProcessHandle currentProcess = ProcessHandle.current();
        this.pid = currentProcess.pid();

        // # 2. oshi
        if (this.pid > 0) { return this.pid; }
        this.pid = systemInfo.getOperatingSystem().getProcessId();

        return this.pid;
    }

    /**
     * OS 의 CPU 를 가져온다.
     */
    private void fillSystemCpu(CentralProcessor processor, PerfDto perfDto) {
        long[] prevTicks = processor.getSystemCpuLoadTicks();
        Util.sleep(1000);
        // long[] ticks = processor.getSystemCpuLoadTicks();
        perfDto.setCpuLoad(Math.round(processor.getSystemCpuLoadBetweenTicks(prevTicks) * 100 * 100) / 100.0); // digit 2
    }

    /**
     * OS 의 Memory 를 가져온다.
     */
    private void fillSystemMem(GlobalMemory memory, PerfDto perfDto) {
        perfDto.setMemTotal(memory.getTotal());
        perfDto.setMemUse(memory.getTotal() - memory.getAvailable());

//        switch (SystemInfo.getCurrentPlatform()) {
//            case WINDOWS:
//            case WINDOWSCE:
//                solOsPerfDto.setSwapTotal(memory.getVirtualMemory().getVirtualMax());
//                solOsPerfDto.setSwapUse(memory.getVirtualMemory().getVirtualInUse());
//                break;
//            default:
//                solOsPerfDto.setSwapTotal(memory.getVirtualMemory().getSwapTotal());
//                solOsPerfDto.setSwapUse(memory.getVirtualMemory().getSwapUsed());
//                break;
//        }
    }

    private OSProcess findProcess(long pid) {
        return systemInfo.getOperatingSystem().getProcess((int)pid);
    }

    private void initSunOsBean() {
        if (sunOsBean == null && !osBeanChecked) {
            OperatingSystemMXBean osBean = java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            osBeanChecked = true;
            if (osBean instanceof com.sun.management.OperatingSystemMXBean bean) {
                sunOsBean = bean;
            }
        }
    }

    private static double toPercent(double ratio) {
        return roundTo(ratio * PERCENT, 2);
    }

    private static double roundTo(double value, int digits) {
        double m = Math.pow(10, digits);
        return Math.round(value * m) / m;
    }

}
