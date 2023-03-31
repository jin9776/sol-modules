package sol.link.module.snmp;

import org.junit.jupiter.api.Test;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;

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
}