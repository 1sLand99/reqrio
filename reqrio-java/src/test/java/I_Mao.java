import com.google.gson.JsonPrimitive;
import org.xllgl2017.*;

public class I_Mao {
    static Fingerprint buildFingerprint() throws Exception {
        CustomFingerprint finger = new CustomFingerprint();
        finger.addSuite(0xcaca);
        finger.addSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        finger.addSuite(CipherSuite.TLS_AES_256_GCM_SHA384);
        finger.addSuite(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        finger.addSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        finger.addSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        finger.addSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        finger.addSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        finger.addSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        finger.addSuite(CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        finger.addSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        finger.addSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        finger.addSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        finger.addSuite(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        finger.addSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        finger.addSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);

        finger.addExtension(0x1a1a);
        finger.addExtension(ExtensionType.ServerName);
        finger.addExtension(ExtensionType.ExtendMasterSecret);
        finger.addExtension(ExtensionType.RenegotiationInfo);
        finger.addExtension(ExtensionType.SupportedGroup);
        finger.addExtension(ExtensionType.EcPointFormats);
        finger.addExtension(ExtensionType.SessionTicket);
        finger.addExtension(ExtensionType.ApplicationLayerProtocolNegotiation);
        finger.addExtension(ExtensionType.StatusRequest);
        finger.addExtension(ExtensionType.SignatureAlgorithms);
        finger.addExtension(ExtensionType.SignedCertificateTimestamp);
        finger.addExtension(ExtensionType.KeyShare);
        finger.addExtension(ExtensionType.PskKeyExchangeMode);
        finger.addExtension(ExtensionType.SupportedVersions);
        finger.addExtension(ExtensionType.CompressionCertificate);
        finger.addExtension(ExtensionType.ApplicationSettingOld);
        finger.addExtension(0x3a3a, new JsonPrimitive("[0]"));
        finger.addExtension(ExtensionType.Padding);

        finger.addSupportedGroup(0xeaea);
        finger.addSupportedGroup(SupportGroup.X25519);
        finger.addSupportedGroup(SupportGroup.Secp256r1);
        finger.addSupportedGroup(SupportGroup.Secp384r1);

        finger.addEcPointFormat(EcPointFormat.UNCOMPRESSED);

        finger.addAlgorithm(Algorithm.ECDSA_SECP256R1_SHA256);
        finger.addAlgorithm(Algorithm.RSA_PSS_RSAE_SHA256);
        finger.addAlgorithm(Algorithm.RSA_PKCS1_SHA256);
        finger.addAlgorithm(Algorithm.ECDSA_SECP384R1_SHA384);
        finger.addAlgorithm(Algorithm.RSA_PSS_RSAE_SHA384);
        finger.addAlgorithm(Algorithm.RSA_PKCS1_SHA384);
        finger.addAlgorithm(Algorithm.RSA_PSS_RSAE_SHA512);
        finger.addAlgorithm(Algorithm.RSA_PKCS1_SHA512);

        finger.addSupportedVersion(0xdada);
        finger.addSupportedVersion(Version.TLS_1_3);
        finger.addSupportedVersion(Version.TLS_1_2);
        finger.addSupportedVersion(Version.TLS_1_1);
        finger.addSupportedVersion(Version.TLS_1_0);

        return Fingerprint.fromCustom(finger, "");
    }


    public static void main(String[] args) {

    }
}
