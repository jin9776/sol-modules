package sol.link.module.snmp.custom;

import lombok.extern.slf4j.Slf4j;
import org.snmp4j.CommunityTarget;
import org.snmp4j.DirectUserTarget;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.Target;
import org.snmp4j.fluent.TargetBuilder;
import org.snmp4j.security.*;
import org.snmp4j.security.nonstandard.PrivAES192With3DESKeyExtension;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.tls.TlsTmSecurityCallback;
import org.snmp4j.transport.tls.TlsX509CertifiedTarget;
import sol.link.module.snmp.security.PrivAES192C;
import sol.link.module.snmp.security.PrivAES256C;

import java.security.cert.X509Certificate;
import java.util.Arrays;

@Slf4j
public class TargetBuilder2<A extends Address>{
    protected final SnmpBuilder2 snmpBuilder;
    protected A address;
    protected OctetString securityName;
    protected TargetBuilder.SnmpVersion snmpVersion;
    protected Target<A> target;
    protected long timeoutMillis;
    protected int retries;
    protected int maxSizeRequestPDU;

    public TargetBuilder2(SnmpBuilder2 snmpBuilder) {
        this.snmpVersion = TargetBuilder.SnmpVersion.v3;
        this.timeoutMillis = SNMP4JSettings.getDefaultTimeoutMillis();
        this.retries = SNMP4JSettings.getDefaultRetries();
        this.maxSizeRequestPDU = SNMP4JSettings.getMaxSizeRequestPDU();
        this.snmpBuilder = snmpBuilder;
    }

    protected TargetBuilder2(SnmpBuilder2 snmpBuilder, A address) {
        this.snmpVersion = TargetBuilder.SnmpVersion.v3;
        this.timeoutMillis = SNMP4JSettings.getDefaultTimeoutMillis();
        this.retries = SNMP4JSettings.getDefaultRetries();
        this.maxSizeRequestPDU = SNMP4JSettings.getMaxSizeRequestPDU();
        this.snmpBuilder = snmpBuilder;
        this.address = address;
    }

    public static <A extends Address> TargetBuilder2<A> forAddress(SnmpBuilder2 snmpBuilder, A address) {
        return new TargetBuilder2<>(snmpBuilder, address);
    }

    public TargetBuilder2<A> address(A address) {
        this.address = address;
        return this;
    }

    public TargetBuilder2<A> v1() {
        this.snmpVersion = TargetBuilder.SnmpVersion.v1;
        return this;
    }

    public TargetBuilder2<A> v2c() {
        this.snmpVersion = TargetBuilder.SnmpVersion.v2c;
        return this;
    }

    public TargetBuilder2<A> v3() {
        this.snmpVersion = TargetBuilder.SnmpVersion.v3;
        return this;
    }

    public TargetBuilder2<A> timeout(long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        return this;
    }

    public TargetBuilder2<A> retries(int retries) {
        this.retries = retries;
        return this;
    }

    public void maxSizeRequestPDU(int maxSizeRequestPDU) {
        this.maxSizeRequestPDU = maxSizeRequestPDU;
    }

    public TargetBuilder2<A> community(OctetString snmpV1V2Community) {
        this.securityName = snmpV1V2Community;
        if (this.snmpVersion == TargetBuilder.SnmpVersion.v3) {
            this.snmpVersion = TargetBuilder.SnmpVersion.v2c;
        }

        this.target = new CommunityTarget<>(this.address, this.securityName);
        return this;
    }

    public DirectUserBuilder user(String securityName) {
        return this.user((String)securityName, (byte[])null);
    }

    public DirectUserBuilder user(String securityName, byte[] authoritativeEngineID) {
        return this.user(new OctetString(securityName), authoritativeEngineID);
    }

    public DirectUserBuilder user(OctetString securityName) {
        return this.user(securityName, null);
    }

    public DirectUserBuilder user(OctetString securityName, byte[] authoritativeEngineID) {
        this.snmpVersion = TargetBuilder.SnmpVersion.v3;
        return new DirectUserBuilder(securityName, authoritativeEngineID);
    }

    public TlsTargetBuilder tls(String identity) {
        return this.tls(new OctetString(identity));
    }

    public TlsTargetBuilder tls(OctetString identity) {
        return new TlsTargetBuilder(identity);
    }

    public TlsTargetBuilder dtls(String identity) {
        return this.dtls(new OctetString(identity));
    }

    public TlsTargetBuilder dtls(OctetString identity) {
        return new TlsTargetBuilder(identity);
    }

    public Target<A> build() {
        this.target.setTimeout(this.timeoutMillis);
        this.target.setRetries(this.retries);
        this.target.setVersion(this.snmpVersion.getVersion());
        return this.target;
    }

    public PduBuilder2 pdu() {
        return new PduBuilder2(this);
    }

    public class DirectUserBuilder {
        private byte[] authoritativeEngineID;
        private final OctetString securityName;
        private TargetBuilder.AuthProtocol authenticationProtocol;
        private PrivProtocol2 privacyProtocol;
        private OctetString authPassword;
        private OctetString privPassword;

        protected DirectUserBuilder(OctetString securityName) {
            this.securityName = securityName;
        }

        protected DirectUserBuilder(OctetString securityName, byte[] authoritativeEngineID) {
            this.authoritativeEngineID = authoritativeEngineID;
            this.securityName = securityName;
        }

        public DirectUserBuilder auth(TargetBuilder.AuthProtocol authenticationProtocol) {
            this.authenticationProtocol = authenticationProtocol;
            return this;
        }

        public DirectUserBuilder priv(PrivProtocol2 privacyProtocol) {
            this.privacyProtocol = privacyProtocol;
            return this;
        }

        public DirectUserBuilder authPassphrase(String authPassword) {
            return this.authPassphrase(OctetString.fromString(authPassword));
        }

        public DirectUserBuilder authPassphrase(OctetString authPassword) {
            this.authPassword = authPassword;
            return this;
        }

        public DirectUserBuilder privPassphrase(String privPassword) {
            return this.privPassphrase(OctetString.fromString(privPassword));
        }

        public DirectUserBuilder privPassphrase(OctetString privPassword) {
            this.privPassword = privPassword;
            return this;
        }

        public TargetBuilder2<A> done() {
            if (this.authoritativeEngineID == null) {
                log.warn("targetBuilder : authoritativeEngineID is null. discover AuthoritativeEngineID.");
                this.authoritativeEngineID = TargetBuilder2.this.snmpBuilder.getSnmp().discoverAuthoritativeEngineID(TargetBuilder2.this.address, TargetBuilder2.this.timeoutMillis);
                if (this.authoritativeEngineID == null) {
                    log.error("targetBuilder : authoritativeEngineID is null.");
                } else {
                    log.info("targetBuilder : authoritativeEngineID is {}", Arrays.toString(this.authoritativeEngineID));
                }
            }

            byte[] authKey = null;
            byte[] privKey = null;
            SecurityProtocols securityProtocols = TargetBuilder2.this.snmpBuilder.getSecurityProtocols();
            if (this.authenticationProtocol != null && this.authPassword != null) {
                if (this.authoritativeEngineID == null) {
                    throw new IllegalArgumentException("Authoritative Engine ID not provided");
                }

                authKey = securityProtocols.passwordToKey(this.authenticationProtocol.getProtocolID(), this.authPassword, this.authoritativeEngineID);
                if (this.privacyProtocol != null && this.privPassword != null) {
                    privKey = securityProtocols.passwordToKey(this.privacyProtocol.getProtocolID(), this.authenticationProtocol.getProtocolID(), this.privPassword, this.authoritativeEngineID);
                }
            }

            if (this.authenticationProtocol != null && authKey != null) {
                if (this.privacyProtocol != null && privKey != null) {
                    TargetBuilder2.this.target = new DirectUserTarget<>(TargetBuilder2.this.address, this.securityName, this.authoritativeEngineID, securityProtocols.getAuthenticationProtocol(this.authenticationProtocol.getProtocolID()), new OctetString(authKey), securityProtocols.getPrivacyProtocol(this.privacyProtocol.getProtocolID()), new OctetString(privKey));
                } else {
                    TargetBuilder2.this.target = new DirectUserTarget<>(TargetBuilder2.this.address, this.securityName, this.authoritativeEngineID, securityProtocols.getAuthenticationProtocol(this.authenticationProtocol.getProtocolID()), new OctetString(authKey), (PrivacyProtocol)null, (OctetString)null);
                }
            } else {
                TargetBuilder2.this.target = new DirectUserTarget<>(TargetBuilder2.this.address, this.securityName, this.authoritativeEngineID, (AuthenticationProtocol)null, (OctetString)null, (PrivacyProtocol)null, (OctetString)null);
            }

            return TargetBuilder2.this;
        }
    }

    public class TlsTargetBuilder {
        private final OctetString identity;
        private OctetString serverFingerprint;
        private OctetString clientFingerprint;
        private TlsTmSecurityCallback<X509Certificate> tlsTmSecurityCallback;

        protected TlsTargetBuilder(OctetString identity) {
            this.identity = identity;
        }

        public TlsTargetBuilder serverFingerprint(OctetString fingerprint) {
            this.serverFingerprint = fingerprint;
            return this;
        }

        public TlsTargetBuilder clientFingerprint(OctetString fingerprint) {
            this.clientFingerprint = fingerprint;
            return this;
        }

        public TlsTargetBuilder securityCallback(TlsTmSecurityCallback<X509Certificate> tlsTmSecurityCallback) {
            this.tlsTmSecurityCallback = tlsTmSecurityCallback;
            return this;
        }

        public TargetBuilder2<A> done() {
            TargetBuilder2.this.target = new TlsX509CertifiedTarget(TargetBuilder2.this.address, this.identity, this.serverFingerprint, this.clientFingerprint, this.tlsTmSecurityCallback);
            return TargetBuilder2.this;
        }
    }

    public enum PrivProtocol2 {
        des("DES", PrivDES.ID),
        _3des("3DES", Priv3DES.ID),
        aes128("AES-128", PrivAES128.ID),
        aes192("AES-192", PrivAES192.ID),
        aes256("AES-256", PrivAES256.ID),
        aes192c("AES-192-C", PrivAES192C.ID),
        aes256c("AES-256-C", PrivAES256C.ID),
        aes192with3DESKeyExtension("AES-192-3DESkeyext", PrivAES192With3DESKeyExtension.ID),
        aes256with3DESKeyExtension("AES-256-3DESkeyext", PrivAES256With3DESKeyExtension.ID);

        private final OID protocolID;
        private final String name;

        private PrivProtocol2(String name, OID protocolID) {
            this.name = name;
            this.protocolID = protocolID;
        }

        public OID getProtocolID() {
            return this.protocolID;
        }

        public String getName() {
            return this.name;
        }
    }
}
