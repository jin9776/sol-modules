package sol.link.module.snmp.oid;

import lombok.Getter;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

@Getter
public class MibContainer {
    private String groupName;
    private String item;
    private String name;
    private boolean pduWalk;
    private OID oid;
    private OID subOid;
    private VariableBinding[] curResult;
    // 결과 값이 M / G 등인 경우 단위를 반영해 주기 위해
    private double resultUnit = 1;
    private boolean useResultUnit = false;

    private OidCollectType oidCollectType = OidCollectType.MibTree;

    /**
     * Oid 공식
     */
    private String oidOfcl;
    /**
     * Oid 공식의 결과 타입 (ex: num, str 등 )
     */
    private String oidOfclDataKnd;

    public MibContainer(String groupName, String item, String name, OID oid) {
        this(groupName, item, name, false, oid, null);
    }
    public MibContainer(String groupName, String item, String name, boolean isPduWalk, OID oid) {
        this(groupName, item, name, isPduWalk, oid, null);
    }
    public MibContainer(String groupName, String item, String name, boolean isPduWalk, OID oid, OID subOid){
        this.groupName = groupName;
        this.name = name;
        this.item = item;
        this.pduWalk = isPduWalk;
        this.oid = oid;
        this.subOid = subOid;
        this.oidCollectType = OidCollectType.MibTree;
    }

    public MibContainer(String groupName, String item, String name, String oidOfcl, String oidOfclDataKnd){
        this(groupName, item, name, false, oidOfcl, oidOfclDataKnd);
    }
    public MibContainer(String groupName, String item, String name, boolean isPduWalk, String oidOfcl, String oidOfclDataKnd){
        this.groupName = groupName;
        this.name = name;
        this.item = item;
        this.pduWalk = isPduWalk;
        this.oidOfcl = oidOfcl;
        this.oidOfclDataKnd = oidOfclDataKnd;
        this.oidCollectType = OidCollectType.Official;
    }


    public void setResult(VariableBinding result) {
        this.curResult = new VariableBinding[] {result};
    }

    public void setWalkResult(VariableBinding[] result) {
        this.curResult = result;
    }

    public void setResultUnit(double resultUnit) {
        this.resultUnit = resultUnit;
        this.useResultUnit = true;
    }
}
