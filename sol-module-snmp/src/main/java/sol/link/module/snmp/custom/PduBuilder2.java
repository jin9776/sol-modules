package sol.link.module.snmp.custom;

import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.util.DefaultPDUFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PduBuilder2 {
    protected final TargetBuilder2<?> targetBuilder;
    protected OctetString contextEngineID;
    protected OctetString contextName;
    protected int pduType = -96;
    protected List<VariableBinding> vbs = new ArrayList<>();

    protected PduBuilder2(TargetBuilder2<?> targetBuilder) {
        this.targetBuilder = targetBuilder;
    }

    public PduBuilder2 contextName(String contextName) {
        return this.contextName(OctetString.fromString(contextName));
    }

    public PduBuilder2 contextName(OctetString contextName) {
        this.contextName = contextName;
        return this;
    }

    public PduBuilder2 contextEngineID(byte[] contextEngineID) {
        return this.contextEngineID(OctetString.fromByteArray(contextEngineID));
    }

    public PduBuilder2 contextEngineID(OctetString contextEngineID) {
        this.contextEngineID = contextEngineID;
        return this;
    }

    public PduBuilder2 type(int pduType) {
        this.pduType = pduType;
        return this;
    }

    public PduBuilder2 oid(OID... oids) {
        OID[] var2 = oids;
        int var3 = oids.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            OID oid = var2[var4];
            this.vbs.add(new VariableBinding(oid));
        }

        return this;
    }

    public PduBuilder2 oids(String... oids) {
        String[] var2 = oids;
        int var3 = oids.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            String objectID = var2[var4];
            this.vbs.add(new VariableBinding(new OID(objectID)));
        }

        return this;
    }

    public PduBuilder2 vb(OID oid, Variable value) {
        this.vbs.add(new VariableBinding(oid, value));
        return this;
    }

    public PduBuilder2 vbs(VariableBinding... vbs) {
        Collections.addAll(this.vbs, vbs);
        return this;
    }

    public PDU build() {
        PDU pdu = DefaultPDUFactory.createPDU(this.targetBuilder.snmpVersion.getVersion());
        if (pdu instanceof ScopedPDU) {
            ScopedPDU scopedPDU = (ScopedPDU)pdu;
            if (this.contextEngineID != null) {
                scopedPDU.setContextEngineID(this.contextEngineID);
            }

            scopedPDU.setContextName(this.contextName);
        }

        pdu.setType(this.pduType);
        pdu.setVariableBindings(this.vbs);
        return pdu;
    }
}
