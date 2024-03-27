package sol.link.module.snmp.security;

import org.snmp4j.security.nonstandard.NonStandardSecurityProtocol;
import org.snmp4j.security.nonstandard.PrivAESWith3DESKeyExtension;
import org.snmp4j.smi.OID;

import java.io.Serial;

public class PrivAES256C extends PrivAESWith3DESKeyExtension implements NonStandardSecurityProtocol {
    @Serial
    private static final long serialVersionUID = -4678800188622949136L;
    public static OID ID;
    private OID oid;

    public PrivAES256C() {
        super(32);
    }

    @Override
    public OID getID() {
        return this.oid == null ? this.getDefaultID() : this.oid;
    }

    @Override
    public void setID(OID newID) {
        this.oid = new OID(newID);
    }

    public OID getDefaultID() {
        return (OID)ID.clone();
    }

    static {
        ID = new OID(new int[]{1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 2});
    }
}
