package sol.link.perfmon;

import com.google.protobuf.Empty;
import io.grpc.stub.StreamObserver;
import lombok.Synchronized;
import lombok.extern.slf4j.Slf4j;
import sol.link.perfmon.dto.PerfDto;
import sol.link.proto.PerfMetric;
import sol.link.proto.PerfMonServiceGrpc;

@Slf4j
public class PerfMetricHelper {

    /**
     * PerfDto -> PerfMetric
     */
    public static PerfMetric.Builder createPerfMetric(PerfDto perfDto) {
        return PerfMetric.newBuilder()
                .setCpuRate(perfDto.getCpuLoad()).setProcCoreCpuRate(perfDto.getProcessCoreCpuLoad()).setCoreNum(perfDto.getCoreCnt())
                .setMemUseRate(perfDto.getMemUseRate()).setMemTotal(perfDto.getMemTotal()).setMemUsed(perfDto.getMemUse())
                .setProcHeapUseRate(perfDto.getHeapUseRate()).setProcHeapTotal(perfDto.getHeapTotal()).setProcHeapUsed(perfDto.getHeapUse())
                .setPid(perfDto.getProcessPid())
                .setProcCpuRate(perfDto.getProcessCpuLoad()).setProcMemUseRate(perfDto.getProcessMemUseRate()).setProcThreadCount(perfDto.getProcessThreadCnt());
    }

    @Synchronized
    public static void recreateStream(StreamObserver<PerfMetric> requestObserver, PerfMonServiceGrpc.PerfMonServiceStub perfMonServiceStub) {
        cleanup(requestObserver);

        StreamObserver<Empty> responseObserver = new StreamObserver<Empty>() {
            @Override
            public void onNext(Empty value) {
                log.debug("perf-mon grpc response: ok");
            }

            @Override
            public void onError(Throwable t) {
                log.error("perf-mon grpc response: {}", t.getMessage());
            }

            @Override
            public void onCompleted() {
                log.debug("perf-mon grpc response: completed");
            }
        };
        requestObserver = perfMonServiceStub.metricStream(responseObserver);
    }

    @Synchronized
    public static void cleanup(StreamObserver<PerfMetric> requestObserver) {
        if (requestObserver != null) {
            requestObserver.onCompleted();
            requestObserver = null;
        }
    }
}
