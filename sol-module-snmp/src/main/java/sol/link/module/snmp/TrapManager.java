package sol.link.module.snmp;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.snmp4j.CommandResponder;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;

@Getter
public class TrapManager {

    @Setter(AccessLevel.NONE)
    private MultiThreadedMessageDispatcher dispatcher;

    private Snmp snmpSocket = null;
    @Setter
    private int port = 162;
    @Setter
    private String address = "0.0.0.0";
    /**
     * tcp / udp(default)
     */
    @Setter
    private String protocol = "udp";

    private int snmpSecurityLevel = 0, snmpAuthType = 1, snmpEncryptType = 1;
    private String snmpUserId = "public", snmpAuthKey = null, snmpEncryptKey = null;

    @Setter(AccessLevel.NONE)
    private ThreadPool threadPool;
    private int threadPoolSize = 10;

    /**
     * trap 메세지를 수신한다.
     * @throws IOException
     */
    public void listen() throws IOException {
        if (!this.protocol.equalsIgnoreCase("UDP") && !this.protocol.equalsIgnoreCase("TCP")) {
            throw new IllegalArgumentException("protocol is not tcp or udp ::: value=" + this.protocol);
        }

        threadPool = ThreadPool.create("TrapPool", this.threadPoolSize);
        dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

        Address listenAddress = GenericAddress.parse(String.format("%s:%s/%d", this.protocol, this.address, this.port));
        TransportMapping<?> transport;
        if (listenAddress instanceof UdpAddress) {
            transport = new DefaultUdpTransportMapping((UdpAddress)listenAddress);
        } else {
            transport = new DefaultTcpTransportMapping((TcpAddress)listenAddress);
        }

        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
        usm.setEngineDiscoveryEnabled(true);

        snmpSocket = new Snmp(dispatcher, transport);
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));
        SecurityModels.getInstance().addSecurityModel(usm);

        // add user to the USM
        OID authId = null, privId = null;
        if (this.snmpAuthType == 1)
            authId = AuthSHA.ID;
        else if (this.snmpAuthType == 2)
            authId = AuthMD5.ID;

        if (this.snmpEncryptKey != null && !this.snmpEncryptKey.isEmpty()) {
            switch (this.snmpEncryptType) {
                case 1:
                    privId = PrivAES128.ID;
                    break;
                case 2:
                    privId = PrivDES.ID;
                    break;
                case 3:
                    privId = PrivAES192.ID;
                    break;
                case 4:
                    privId = PrivAES256.ID;
                    break;
            }
        }

        UsmUser usmUser = null;
        if (this.snmpSecurityLevel == 0) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), null, null, null, null);
        } else if (this.snmpSecurityLevel == 1) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), authId, new OctetString(this.snmpAuthKey), null, null);
        } else if (this.snmpSecurityLevel == 2) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), authId, new OctetString(this.snmpAuthKey), privId, new OctetString(this.snmpEncryptKey));
        }

        snmpSocket.getUSM().addUser(new OctetString(this.snmpUserId), usmUser);

        snmpSocket.listen();
    }

    /**
     * 메세지 수신 class 를 등록한다.
     * 주의) listen 후에 등록 한다.
     */
    public void addCommandResponder(CommandResponder respClass) {
        this.snmpSocket.addCommandResponder(respClass);
    }
}
