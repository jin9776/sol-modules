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

@Setter
@Getter
public class TrapManager {

    @Setter(AccessLevel.NONE)
    private MultiThreadedMessageDispatcher dispatcher;
    @Setter(AccessLevel.NONE)
    private Snmp snmpSocket = null;

    private int port = 162;
    private String address = "0.0.0.0";
    /**
     * tcp / udp(default)
     */
    private String protocol = "udp";

    private int snmpSecurityLevel = 0;
    private int snmpAuthType = 1;
    private  int snmpEncryptType = 1;
    private String snmpUserId = "public";
    private String snmpAuthKey = null;
    private String snmpEncryptKey = null;

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

        // add user to the USM
        OID authId = null, privId = null;
        if (this.snmpAuthType == 1) {
            authId = AuthSHA.ID;
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        } else if (this.snmpAuthType == 2) {
            authId = AuthMD5.ID;
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
        }

        if (this.snmpEncryptKey != null && !this.snmpEncryptKey.isEmpty()) {
            switch (this.snmpEncryptType) {
                case 1:
                    privId = PrivAES128.ID;
                    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES128());
                    break;
                case 2:
                    privId = PrivDES.ID;
                    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivDES());
                    break;
                case 3:
                    privId = PrivAES192.ID;
                    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
                    break;
                case 4:
                    privId = PrivAES256.ID;
                    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
                    break;
            }
        }

        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);

        UsmUser usmUser = null;
        if (this.snmpSecurityLevel == 0) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), null, null, null, null);
        } else if (this.snmpSecurityLevel == 1) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), authId, new OctetString(this.snmpAuthKey), null, null);
        } else if (this.snmpSecurityLevel == 2) {
            usmUser = new UsmUser(new OctetString(this.snmpUserId), authId, new OctetString(this.snmpAuthKey), privId, new OctetString(this.snmpEncryptKey));
        }

        SecurityModels.getInstance().addSecurityModel(usm);
        usm.addUser(usmUser);

        snmpSocket = new Snmp(dispatcher, transport);
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        //snmpSocket.getUSM().addUser(new OctetString(this.snmpUserId), usmUser);

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
