package sol.link.module.snmp;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.fluent.SnmpBuilder;
import org.snmp4j.fluent.SnmpCompletableFuture;
import org.snmp4j.fluent.TargetBuilder;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Accessors(chain = true)
@Getter
@Setter
@ToString
public class SnmpManager implements AutoCloseable {
    private int NON_REPEATERS = 0;
    private int MAX_REPETITIONS = 100;

    @Setter(AccessLevel.NONE)
    private Snmp snmpSocket;
    private int snmpVer = SnmpConstants.version2c;
    private int port = 161;
    private String address = "127.0.0.1";
    private String roCommunity = "public";
    private int snmpSecurityLevel = 0, snmpAuthType = 1, snmpEncryptType = 1;
    private String snmpUserId = null, snmpAuthKey = null, snmpEncryptKey = null;
    /*
        재시도 횟수
     */
    private int retries = 0;
    private long timeout = 1000;
    private int engineBoots = 0;

    private UsmUserEntry usmUserEntry = null;
    private OctetString targetEngineId = null;
    private OctetString localEngineId = null;
    private boolean threadDispatcher = false;

    Target<?> target = null;
    TargetBuilder<?> targetBuilder = null;
    byte[] snmpEngineId = null;

    public void connect() throws IOException{
        if (this.snmpSocket != null) {
            this.snmpSocket.close();
            this.snmpSocket = null;
        }

        //int availableProcessors = Runtime.getRuntime().availableProcessors();
        Address targetAddress = GenericAddress.parse(String.format("udp:%s/%s", this.address, this.port));

        SnmpBuilder snmpBuilder = new SnmpBuilder();
        snmpBuilder.udp(); //.threads(availableProcessors);

        targetBuilder = snmpBuilder.target(targetAddress);
        if (this.snmpVer == SnmpConstants.version3) {
            if (this.localEngineId != null) {
                snmpSocket = snmpBuilder.securityProtocols(SecurityProtocols.SecurityProtocolSet.maxCompatibility).v3().usm(this.localEngineId, this.engineBoots).build();
            } else {
                snmpSocket = snmpBuilder.securityProtocols(SecurityProtocols.SecurityProtocolSet.maxCompatibility).v3().usm().build();
            }

            byte[] targetEngineId = snmpSocket.discoverAuthoritativeEngineID(targetAddress, this.timeout);
            snmpEngineId = null;
            if (this.targetEngineId == null) {
                snmpEngineId = targetEngineId;
            } else {
                snmpEngineId = this.targetEngineId.getValue();
            }

            TargetBuilder<?>.DirectUserBuilder userBuilder = null;
            if (snmpEngineId == null) {
                userBuilder = targetBuilder.user(this.snmpUserId);
            } else {
                userBuilder = targetBuilder.user(this.snmpUserId, snmpEngineId);
            }

            TargetBuilder.AuthProtocol authProtocol = null;
            switch (this.snmpAuthType) {
                case 0: break;
                case 1: authProtocol = TargetBuilder.AuthProtocol.sha1; break;
                case 2: authProtocol = TargetBuilder.AuthProtocol.md5; break;
                case 3: authProtocol = TargetBuilder.AuthProtocol.hmac128sha224; break;
                case 4: authProtocol = TargetBuilder.AuthProtocol.hmac192sha256; break;
                case 5: authProtocol = TargetBuilder.AuthProtocol.hmac256sha384; break;
                case 6: authProtocol = TargetBuilder.AuthProtocol.hmac384sha512; break;
                default: throw new UnsupportedOperationException("Unknown auth protocol : " + this.snmpAuthType);
            }

            if (this.snmpSecurityLevel == 1) {
                userBuilder.auth(authProtocol).authPassphrase(this.snmpAuthKey);
            } else if (this.snmpSecurityLevel == 2) {
                userBuilder.auth(authProtocol).authPassphrase(this.snmpAuthKey);

                switch (this.snmpEncryptType) {
                    case 1: userBuilder.priv(TargetBuilder.PrivProtocol.aes128).privPassphrase(this.snmpEncryptKey); break;
                    case 2: userBuilder.priv(TargetBuilder.PrivProtocol.des).privPassphrase(this.snmpEncryptKey); break;
                    case 3: userBuilder.priv(TargetBuilder.PrivProtocol.aes192).privPassphrase(this.snmpEncryptKey); break;
                    case 4: userBuilder.priv(TargetBuilder.PrivProtocol.aes256).privPassphrase(this.snmpEncryptKey); break;
                    case 5: userBuilder.priv(TargetBuilder.PrivProtocol._3des).privPassphrase(this.snmpEncryptKey); break;
                    case 6: userBuilder.priv(TargetBuilder.PrivProtocol.aes192with3DESKeyExtension).privPassphrase(this.snmpEncryptKey); break;
                    case 7: userBuilder.priv(TargetBuilder.PrivProtocol.aes256with3DESKeyExtension).privPassphrase(this.snmpEncryptKey); break;
                    default: throw new UnsupportedOperationException("Unknown privacy protocol : " + this.snmpEncryptType);
                }
            }
            this.target = userBuilder.done().timeout(this.timeout).retries(this.retries).build();

        } else {
            if (this.snmpVer == SnmpConstants.version2c) {
                this.targetBuilder.v2c();
                snmpBuilder.v2c();
            } else {
                this.targetBuilder.v1();
                snmpBuilder.v1();
            }
            snmpSocket = snmpBuilder.build();
            this.target = snmpBuilder.target(targetAddress).community(new OctetString(this.roCommunity))
                    .timeout(this.timeout).retries(this.retries).build();
        }
        this.target.setVersion(this.snmpVer);
    }

    /**
     * snmp socket connect
     * @throws IOException
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Deprecated(since = "2.x", forRemoval = true)
    public void connect2(TransportMapping transportMapping) throws IOException {
        if (this.snmpVer == SnmpConstants.version3) {
            if (transportMapping instanceof DefaultUdpTransportMapping) {
                ((DefaultUdpTransportMapping)transportMapping).setAsyncMsgProcessingSupported(false);
            }

            /*
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
             */

            if (this.threadDispatcher) {
                snmpSocket = new Snmp(transportMapping);
                snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv1());
                snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
                snmpSocket.getMessageDispatcher().addMessageProcessingModel(new MPv3());
            } else {
                snmpSocket = new Snmp(transportMapping);
            }

            USMFactory.getInstance(this.snmpSocket, this.localEngineId, this.engineBoots);
            transportMapping.listen();

            /*
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());

			    addAuthenticationProtocol(new AuthHMAC128SHA224());
                addAuthenticationProtocol(new AuthHMAC192SHA256());
                addAuthenticationProtocol(new AuthHMAC256SHA384());
                addPrivacyProtocol(new PrivDES());
                addPrivacyProtocol(new PrivAES128());
                addPrivacyProtocol(new PrivAES192());
                addAuthenticationProtocol(new AuthHMAC384SHA512());
                addPrivacyProtocol(new PrivAES256());
                new Priv3DES()
			 */

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

            //snmpSocket.getUSM().addUser(new OctetString(usmUser.getSecurityName()), usmUser);
            this.usmUserEntry = USMFactory.addUser(snmpSocket, usmUser);
        } else {
            snmpSocket = new Snmp(transportMapping);
            transportMapping.listen();
        }

//        if (!transportMapping.isListening()) {
//            transportMapping.listen();
//        }
    }


    @Override
    public void close() {
        try {
//            if (this.usmUserEntry != null) {
//                USMFactory.removeUser(this.snmpSocket, this.usmUserEntry);
//            }
            if (this.snmpSocket != null) {
                for (TransportMapping transportMapping : snmpSocket.getMessageDispatcher().getTransportMappings()) {
                    DefaultUdpTransportMapping defaultUdpTransportMapping = ((DefaultUdpTransportMapping)transportMapping);
                    if (defaultUdpTransportMapping.getListenWorkerTask() != null) {
                        try {
                            defaultUdpTransportMapping.getListenWorkerTask().interrupt();
                        } catch (Exception ignore) {}
                    }
                    if (defaultUdpTransportMapping.getSocketCleaner() != null) {
                        defaultUdpTransportMapping.getSocketCleaner().cancel();
                    }
                }

                this.snmpSocket.close();
            }
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    public VariableBinding[] snmpSet(VariableBinding vb) {
        PDU pdu = this.targetBuilder.pdu().type(PDU.SET).vbs(vb).build();
        try {
            return parseResponse2(SnmpCompletableFuture.send(this.snmpSocket, this.target, pdu));
        } catch (Exception e) {
            log.warn("snmp set {}, msg={}", vb.getOid().toDottedString(), e.getMessage());
            return null;
        }
    }

    /**
     * get snmp
     * @param oids
     * @return response data
     * @throws IOException
     */
    public VariableBinding[] snmpGet(OID... oids) throws IOException {
        PDU pdu = this.targetBuilder.pdu().type(PDU.GET).oid(oids).contextName("").build();
        return parseResponse2(SnmpCompletableFuture.send(this.snmpSocket, this.target, pdu));
        /*
        PDU pdu = createPdu(oids);
        pdu.setType(PDU.GET);
        return parseResponse(send(pdu));
         */
    }
    /**
     * getnext snmp
     * @param oids
     * @return response data
     * @throws IOException
     */
    public VariableBinding[] snmpGetNext(OID... oids) throws IOException {
        PDU pdu = this.targetBuilder.pdu().type(PDU.GETNEXT).oid(oids).contextName("").build();
        return parseResponse2(SnmpCompletableFuture.send(this.snmpSocket, this.target, pdu));
        /*
        PDU pdu = createPdu(oids);
        pdu.setType(PDU.GETNEXT);
        return parseResponse(send(pdu));
         */
    }

    /**
     * getBulk snmp
     * @param oids
     * @return response data
     * @throws IOException
     */
    public VariableBinding[] snmpGetBulk(OID... oids) throws IOException {
        return this.snmpGetBulk(this.NON_REPEATERS, this.MAX_REPETITIONS, oids);
    }

    /**
     * getBulk snmp
     * @param nonRepeaters
     * @param maxRepetitions
     * @param oids
     * @return
     * @throws IOException
     */
    public VariableBinding[] snmpGetBulk(int nonRepeaters, int maxRepetitions, OID... oids) throws IOException {
        PDU pdu = this.targetBuilder.pdu().type(PDU.GETBULK).oid(oids).build();
        pdu.setNonRepeaters(nonRepeaters);
        pdu.setMaxRepetitions(maxRepetitions);
        return parseResponse2(SnmpCompletableFuture.send(this.snmpSocket, this.target, pdu));

        /*
        PDU pdu = createPdu(oids);
        pdu.setType(PDU.GETBULK);
        pdu.setNonRepeaters(nonRepeaters);
        pdu.setMaxRepetitions(maxRepetitions);
        return parseResponse(send(pdu));
         */
    }


    /**
     * walk snmp
     */
    public VariableBinding[] snmpWalk(OID oid) {
        return snmpWalk(NON_REPEATERS, MAX_REPETITIONS, oid);
    }
    public VariableBinding[] snmpWalk(int nonRepeaters, int maxRepetitions, OID oid) {
        DefaultPDUFactory factory = new DefaultPDUFactory();
        if (this.snmpVer == SnmpConstants.version3 || this.snmpVer == SnmpConstants.version2c) {
            factory.setPduType(PDU.GETBULK);
            if (this.snmpVer == SnmpConstants.version3 && this.snmpEngineId != null) {
                factory.setContextEngineID(new OctetString(this.snmpEngineId));
            }
        } else {
            factory.setPduType(PDU.GETNEXT);
        }
        factory.setNonRepeaters(nonRepeaters);
        factory.setMaxRepetitions(maxRepetitions);

        TreeUtils treeUtils = new TreeUtils(this.snmpSocket, factory);
        treeUtils.setIgnoreLexicographicOrder(true);
        List<TreeEvent> events = treeUtils.getSubtree(this.target, oid);
        List<VariableBinding> result = new ArrayList<>();

        // get snmpwalk result
        for (TreeEvent event: events) {
            if (event != null) {
                if (event.isError()) {
                    if (event.getStatus() == -1) {
                        throw new RuntimeException("oid[" + oid + "] " + event.getErrorMessage() + " result:" + result.size() + " timeout:" + this.timeout);
                    } else {
                        log.warn("oid=[{}], status={} : {} ", event.getErrorMessage(), event.getStatus(), event.getVariableBindings());
                    }
                }

                VariableBinding[] varBindings = event.getVariableBindings();
                if (varBindings != null) {
                    result.addAll(Arrays.asList(varBindings));
                }
            }
        }
        return result.stream().toArray(VariableBinding[]::new);
    }
    /**
     * walk snmp
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public VariableBinding[] snmpWalk2(int nonRepeaters, int maxRepetitions, OID oid) {
        DefaultPDUFactory factory = new DefaultPDUFactory();
       // factory.setContextEngineID(new OctetString(""));
       // factory.setContextName(new OctetString(""));

        // v1/v2c와 v3 타켓 인증을 구분
        Target target = null;
        if (this.snmpVer == SnmpConstants.version3) {
            target = getV3Target();
            factory.setPduType(PDU.GETBULK);
            factory.setNonRepeaters(nonRepeaters);
            factory.setMaxRepetitions(maxRepetitions);
        } else if (this.snmpVer == SnmpConstants.version2c) {
            target = getTarget();
            factory.setPduType(PDU.GETBULK);
            factory.setNonRepeaters(nonRepeaters);
            factory.setMaxRepetitions(maxRepetitions);
        } else {
            target = getTarget();
            factory.setPduType(PDU.GETNEXT);
            factory.setNonRepeaters(nonRepeaters);
            factory.setMaxRepetitions(maxRepetitions);
        }

        TreeUtils treeUtils = new TreeUtils(this.snmpSocket, factory);
        treeUtils.setIgnoreLexicographicOrder(true);
        List<TreeEvent> events = treeUtils.getSubtree(target, oid);
        List<VariableBinding> result = new ArrayList<>();

        // get snmpwalk result
        for (TreeEvent event: events) {
            if (event != null) {
                if (event.isError()) {
                    if (event.getStatus() == -1) {
                        throw new RuntimeException("oid[" + oid + "] " + event.getErrorMessage() + " result:" + result.size() + " timeout:" + this.timeout);
                    } else {
                        log.warn("oid=[{}], status={} : {} ", event.getErrorMessage(), event.getStatus(), event.getVariableBindings());
                    }
                }

                VariableBinding[] varBindings = event.getVariableBindings();
                if (varBindings != null) {
                    result.addAll(Arrays.asList(varBindings));
                }
            }
        }
        return result.stream().toArray(VariableBinding[]::new);
    }

    /**
     *  OID 목록으로 PDU를 생성한다.
     */
    private PDU createPdu(OID... oids) {
        PDU pdu = null;
        if (this.snmpVer == SnmpConstants.version3) {
            pdu = new ScopedPDU();
            if (this.targetEngineId != null) {
                ((ScopedPDU) pdu).setContextEngineID(targetEngineId);
            }
        } else {
            pdu = new PDU();
        }

        for (OID oid : oids) {
            pdu.add(new VariableBinding(oid));
        }
        return pdu;
    }

    private VariableBinding[] parseResponse2(SnmpCompletableFuture snmpCompletableFuture) throws RuntimeException {

        try {
            return snmpCompletableFuture.get().getAll().toArray(VariableBinding[]::new);
//            if (snmpCompletableFuture.getResponseEvent().getResponse() == null) {
//                return null;
//            } else {
//                return snmpCompletableFuture.get().getAll().toArray(VariableBinding[]::new);
//            }
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * 결과 파싱
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private VariableBinding[] parseResponse(ResponseEvent event){
        if (event.getResponse() == null) {
            return null;
        } else {
            PDU pdu = event.getResponse();
            VariableBinding[] list = new VariableBinding[pdu.size()];
            for (int i = 0; i < pdu.size(); i++) {
                list[i] = pdu.get(i);
            }
            return list;
        }
    }

    /**
     * SNMP Send
     * @throws IOException
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private ResponseEvent send(PDU pdu) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("SNMP %s Sending Request....", getPduTypeToString(pdu.getType())));
            for (int i = 0; i < pdu.getVariableBindings().size(); i++) {
                log.debug("Oid = " + pdu.get(i));
            }
        }

        // v1/v2c와 v3 타켓 인증을 구분
        Target target = null;
        if (this.snmpVer == SnmpConstants.version3) {
            target = getV3Target();
        }  else {
            target = getTarget();
        }

        ResponseEvent response = snmpSocket.send(pdu, target);

        if (response != null) {
            PDU responsePDU = response.getResponse();
            if (responsePDU != null) {
                int errorStatus = responsePDU.getErrorStatus();

                if(errorStatus == PDU.noError || errorStatus == PDU.noSuchName) {
                    return response;
                }
                else {
                    int errorIndex = responsePDU.getErrorIndex();
                    String errorStatusText = responsePDU.getErrorStatusText();
                    log.error("Error: Request Failed\nError Status = {}\nError Index = {}\nError Status Text = {}", errorStatus, errorIndex, errorStatusText);
                    throw new RuntimeException(errorStatusText);
                }
            }
        }

        throw new RuntimeException("timed out");
    }

    /**
     * pdu type 정의 값을 String 으로 변환해 준다.
     */
    public String getPduTypeToString(int pduType) {
        if (pduType == PDU.GET) {
            return "GET";
        } else if (pduType == PDU.GETNEXT) {
            return "GETNEXT";
        } else if (pduType == PDU.GETBULK) {
            return "GETBULK";
        } else if (pduType == PDU.SET) {
            return "SET";
        } else if (pduType == PDU.RESPONSE) {
            return "RESPONSE";
        } else if (pduType == PDU.V1TRAP) {
            return "V1TRAP";
        } else if (pduType == PDU.INFORM) {
            return "INFORM";
        } else if (pduType == PDU.TRAP) {
            return "TRAP";
        } else if (pduType == PDU.REPORT) {
            return "REPORT";
        } else {
            String warnText = "Not define pdu type";
            log.warn(warnText);
            return warnText;
        }
    }

    /**
     * set snmpVer
     * @param snmpVer 1 ~ 3
     */
    public SnmpManager setSnmpVer(int snmpVer) {
        if (snmpVer == 1 || snmpVer == 0) {
            this.snmpVer = SnmpConstants.version1;
        } else if (snmpVer == 3) {
            this.snmpVer = SnmpConstants.version3;
        } else {
            this.snmpVer = SnmpConstants.version2c;
        }
        return this;
    }

    /**
     * get snmpVer
     * @return 1 ~ 3
     */
    public int getSnmpVer() {
        if (this.snmpVer == SnmpConstants.version1) {
            return 0;
        } else if (this.snmpVer == SnmpConstants.version2c) {
            return 1;
        } else if (this.snmpVer == SnmpConstants.version3) {
            return 3;
        } else {
            throw new IllegalArgumentException("snmp vertsion not range 1-3 ");
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Target getTarget() {
        Address targetAddress = GenericAddress.parse(String.format("udp:%s/%s", address, this.port));
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(this.roCommunity));
        target.setAddress(targetAddress);
        target.setRetries(this.retries);
        target.setTimeout(this.timeout);
        target.setVersion(this.snmpVer);
        return target;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Target getV3Target() {
        Address targetAddress = GenericAddress.parse(String.format("udp:%s/%s", this.address, this.port));
        //byte[] targetEngineID = snmpSocket.discoverAuthoritativeEngineID(targetAddress, 1000);
        UserTarget target = new UserTarget();
        target.setAddress(targetAddress);
        target.setRetries(this.retries);
        target.setTimeout(this.timeout);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(this.snmpSecurityLevel + 1);
        // 상수값이 상이함
        // (이로인해
        // Authentication
        // error가
        // 발생했었음!!!)
        target.setSecurityName(new OctetString(this.snmpUserId));
//        if (this.targetEngineId != null) {
//            target.setAuthoritativeEngineID(targetEngineId.getValue());
//        }
        return target;
    }
}
