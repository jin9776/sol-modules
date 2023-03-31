package sol.link.module.snmp;


import lombok.extern.slf4j.Slf4j;
import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.OctetString;

@Slf4j
public class USMFactory {
    
    private static USM usm;


    public static void getInstance(Snmp snmp){
        getInstance(snmp, null, 0);
    }
    public static void getInstance(Snmp snmp, OctetString engineId){
        getInstance(snmp, engineId, 0);
    }
    public synchronized static void getInstance(Snmp snmp, OctetString engineId, int engineBoots) {
        if (usm == null) {
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
            SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());

            OctetString localEngineID = null;
            if (engineId == null) {
                localEngineID = new OctetString(MPv3.createLocalEngineID());
            } else {
                localEngineID = engineId;
            }
            snmp.setLocalEngine(localEngineID.getValue(), 0, 0);

            usm = new USM(SecurityProtocols.getInstance(), localEngineID, engineBoots);
            SecurityModels.getInstance().addSecurityModel(usm);
            //SecurityModels.getInstance().addSecurityModel(new TSM(localEngineID, false));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ignore) {}
        }
    }

    public synchronized static UsmUserEntry addUser(Snmp snmp, UsmUser user) {
        return addUser(snmp, user, null);
    }
    public synchronized static UsmUserEntry addUser(Snmp snmp, UsmUser user, OctetString engineId) {
        OctetString engineID = engineId;
        UsmUserEntry entry = null;

        byte[] authKey = null;
        byte[] privKey = null;
        String txt;
        if (user.getSecurityName().length() > 32) {
            OctetString var10000 = user.getSecurityName();
            txt = "User '" + var10000 + "' not added because of its too long security name with length " + user.getSecurityName().length();
            log.warn(txt);
            throw new IllegalArgumentException(txt);
        } else {
            if (engineID != null && engineID.length() > 0) {
                if (engineID.length() < 5 || engineID.length() > 32) {
                    txt = "User '" + user.getSecurityName().toString() + "' not added because of an engine ID of incorrect length " + engineID.length();
                    log.warn(txt);
                    throw new IllegalArgumentException(txt);
                }

                if (user.getAuthenticationProtocol() != null) {
                    if (user.isLocalized()) {
                        authKey = user.getAuthenticationPassphrase().getValue();
                    } else {
                        authKey = SecurityProtocols.getInstance().passwordToKey(user.getAuthenticationProtocol(), user.getAuthenticationPassphrase(), engineID.getValue());
                    }

                    if (user.getPrivacyProtocol() != null) {
                        if (user.isLocalized()) {
                            privKey = user.getPrivacyPassphrase().getValue();
                        } else {
                            privKey = SecurityProtocols.getInstance().passwordToKey(user.getPrivacyProtocol(), user.getAuthenticationProtocol(), user.getPrivacyPassphrase(), engineID.getValue());
                        }
                    }
                }
            }

            OctetString userEngineID;
            if (user.isLocalized()) {
                userEngineID = user.getLocalizationEngineID();
            } else {
                userEngineID = engineID == null ? new OctetString() : engineID;
            }

            entry = new UsmUserEntry(user.getSecurityName(), userEngineID, user);
            entry.setAuthenticationKey(authKey);
            entry.setPrivacyKey(privKey);
            snmp.getUSM().getUserTable().addUser(entry);
            //snmp.getUSM().setEngineDiscoveryEnabled(false);
            return entry;
        }
    }

    public synchronized static void removeUser(Snmp snmp, UsmUserEntry usmUserEntry) {
        snmp.getUSM().getUserTable().removeUser(usmUserEntry.getEngineID(), usmUserEntry.getUserName());
    }
}
