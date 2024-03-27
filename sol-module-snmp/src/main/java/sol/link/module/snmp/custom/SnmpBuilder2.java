package sol.link.module.snmp.custom;

import org.snmp4j.Snmp;
import org.snmp4j.fluent.SnmpBuilder;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.Address;
import sol.link.module.snmp.security.PrivAES256C;

public class SnmpBuilder2 extends SnmpBuilder {

    public SnmpBuilder2() {
        super();
    }

    public void initSecurityProtocols() {
        this.securityProtocols.removeAll();
        this.securityProtocols.addDefaultProtocols();
        this.securityProtocols.addPredefinedProtocolSet(SecurityProtocols.SecurityProtocolSet.maxCompatibility);
        this.securityProtocols.addPrivacyProtocol(new PrivAES256C());
    }

    public SecurityProtocols getSecurityProtocols() {
        return this.securityProtocols;
    }

    public Snmp getSnmp() {
        return this.snmp;
    }

    public <A extends Address> TargetBuilder2<A> target2(A address) {
        return TargetBuilder2.forAddress(this, address);
    }
}
