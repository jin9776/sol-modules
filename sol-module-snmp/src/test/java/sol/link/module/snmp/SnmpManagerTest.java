package sol.link.module.snmp;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.snmp4j.PDU;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.fluent.SnmpBuilder;
import org.snmp4j.fluent.SnmpCompletableFuture;
import org.snmp4j.fluent.TargetBuilder;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import sol.link.module.snmp.security.PrivAES256C;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutionException;

@Slf4j
class SnmpManagerTest {

    @Test
    void connectTestV3() throws IOException {

        SnmpManager snmpManager = new SnmpManager();
        snmpManager.setSnmpVer(3).setAddress("192.168.0.206");
        snmpManager.setSnmpUserId("solink1232");
        snmpManager.setSnmpSecurityLevel(2);
        snmpManager.setTimeout(10000);
        snmpManager.setSnmpAuthType(1).setSnmpAuthKey("solink123");
        snmpManager.setSnmpEncryptType(1).setSnmpEncryptKey("solink123");
        // snmpManager.setRoCommunity("solinㅁㅁk");
        snmpManager.connect();
        snmpManager.getSnmpSocket().listen();

        VariableBinding[] result =  snmpManager.snmpGet(new OID(".1.3.6.1.2.1.1.2.0"));
        for (VariableBinding val : result) {
            System.out.println(val.getVariable().toString());
        }
    }

    @Test
    void connectTestV3Aes256() throws IOException {

        SnmpManager snmpManager = new SnmpManager();
        snmpManager.setSnmpVer(3).setAddress("10.33.199.240").setPort(1161);
        snmpManager.setSnmpUserId("asianaidt");
        snmpManager.setSnmpSecurityLevel(2);
        snmpManager.setTimeout(10000);
        snmpManager.setSnmpAuthType(1).setSnmpAuthKey("Asianaidt1!!");
        snmpManager.setSnmpEncryptType(4).setSnmpEncryptKey("Asianaidt1!!");
        // snmpManager.setRoCommunity("solinㅁㅁk");
        snmpManager.connect();
        snmpManager.getSnmpSocket().listen();

        VariableBinding[] result =  snmpManager.snmpGet(new OID(".1.3.6.1.2.1.1.2.0"));
        for (VariableBinding val : result) {
            System.out.println(val.getVariable().toString());
        }
    }

    @Test
    void connectTestV3Aes256short() throws IOException {
        //SecurityProtocols.getInstance().removeAll();
        SNMP4JSettings.setExtensibilityEnabled(true);
        System.setProperty(SecurityProtocols.SECURITY_PROTOCOLS_PROPERTIES, "SecurityProtocolsTest.properties");
        //SecurityProtocols.getInstance().addDefaultProtocols();
        //SnmpManager.setAES256C();
        //SnmpManager.setAES256CExtension();

        SnmpManager snmpManager = new SnmpManager();
        snmpManager.setSnmpVer(3).setAddress("10.33.199.240").setPort(1161);
        snmpManager.setSnmpUserId("asianaidt");
        snmpManager.setSnmpSecurityLevel(2);
        snmpManager.setTimeout(3000);
        snmpManager.setSnmpAuthType(1).setSnmpAuthKey("Asianaidt1!!");
        snmpManager.setSnmpEncryptType(7).setSnmpEncryptKey("Asianaidt1!!");
        // snmpManager.setRoCommunity("solinㅁㅁk");
        //snmpManager.connect2(new DefaultUdpTransportMapping());
        snmpManager.connect();
        snmpManager.getSnmpSocket().listen();

        Collection<OID> collection = SecurityProtocols.getInstance().getSecurityProtocolOIDs(SecurityProtocols.SecurityProtocolType.privacy);
        for (OID data : collection) {
            log.info("@@ PrivOIDs={}", data.toDottedString());
        }

        //VariableBinding[] result =  snmpManager.snmpGet2(new OID(".1.3.6.1.2.1.1.2.0"));
        VariableBinding[] result =  snmpManager.snmpGet(new OID(".1.3.6.1.2.1.1.2.0"));
        for (VariableBinding val : result) {
            System.out.println(val.getVariable().toString());
        }
    }

    @Test
    void connectTestV3Aes256C() throws IOException {
        //SecurityProtocols.getInstance().removeAll();
        //SNMP4JSettings.setExtensibilityEnabled(true);
        //System.setProperty(SecurityProtocols.SECURITY_PROTOCOLS_PROPERTIES, "SecurityProtocolsTest.properties");
        //SecurityProtocols.getInstance().addDefaultProtocols();
        //SnmpManager.setAES256C();
        //SnmpManager.setAES256CExtension();


        SnmpManager snmpManager = new SnmpManager();
        snmpManager.setSnmpVer(3).setAddress("10.33.199.240").setPort(1161);
        snmpManager.setSnmpUserId("asianaidt");
        snmpManager.setSnmpSecurityLevel(2);
        snmpManager.setTimeout(3000);
        snmpManager.setSnmpAuthType(1).setSnmpAuthKey("Asianaidt1!!");
        snmpManager.setSnmpEncryptType(8).setSnmpEncryptKey("Asianaidt1!!");
        // snmpManager.setRoCommunity("solinㅁㅁk");
        //snmpManager.connect2(new DefaultUdpTransportMapping());
        snmpManager.connect();
      //  snmpManager.getSnmpSocket().listen();

        //VariableBinding[] result =  snmpManager.snmpGet2(new OID(".1.3.6.1.2.1.1.2.0"));
        VariableBinding[] result =  snmpManager.snmpGet(new OID(".1.3.6.1.2.1.1.2.0"));
        for (VariableBinding val : result) {
            System.out.println(val.getVariable().toString());
        }
    }

    @Test
    void connectTestV2() throws IOException {

        SnmpManager snmpManager = new SnmpManager();
        snmpManager.setSnmpVer(2).setAddress("192.168.0.9").setPort(161);
        snmpManager.setRoCommunity("solid");
        snmpManager.setTimeout(10000);
        // snmpManager.setRoCommunity("solinㅁㅁk");
        snmpManager.connect();

        snmpManager.getSnmpSocket().listen();

        VariableBinding[] result =  snmpManager.snmpGet(new OID(".1.3.6.1.2.1.1.2.0"));
        for (VariableBinding val : result) {
            System.out.println(val.getVariable().toString());
        }
    }


    @Test
    void sample() throws IOException {
        SNMP4JSettings.setExtensibilityEnabled(true);
        System.setProperty(SecurityProtocols.SECURITY_PROTOCOLS_PROPERTIES, "SecurityProtocolsTest.properties");
        SecurityProtocols securityProtocols = SecurityProtocols.getInstance().addDefaultProtocols();

        String targetAddress = "10.33.199.240/1161";
        String context = "";
        String securityName = "asianaidt";
        String authPasssphrase = "asianaidt";
        String privPasssphrase = "asianaidt";
        String version = "3";
        String[] oids = new String[1];
        oids[0] = ".1.3.6.1.2.1.1.2.0";


        Snmp snmp = new Snmp();


        snmp.close();
    }

}