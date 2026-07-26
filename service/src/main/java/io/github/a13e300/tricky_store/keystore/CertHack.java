package io.github.a13e300.tricky_store.keystore;

import android.content.pm.PackageManager;
import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.Tag;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.util.Pair;

import androidx.annotation.Nullable;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import io.github.a13e300.tricky_store.Config;
import io.github.a13e300.tricky_store.Logger;
import io.github.a13e300.tricky_store.ModuleHash;
import io.github.a13e300.tricky_store.UtilKt;

public final class CertHack {
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final Map<String, KeyBox> keyboxes = new HashMap<>();
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;

    private static final CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (Throwable t) {
            Logger.e("", t);
            throw new RuntimeException(t);
        }
    }

    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;
    // Tag constants matching KeyMint / attestation
    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final int TAG_OS_VERSION = 705;
    private static final int TAG_OS_PATCHLEVEL = 706;
    private static final int TAG_APPLICATION_ID = 709;
    private static final int TAG_ATTESTATION_ID_BRAND = 710;
    private static final int TAG_ATTESTATION_ID_DEVICE = 711;
    private static final int TAG_ATTESTATION_ID_PRODUCT = 712;
    private static final int TAG_ATTESTATION_ID_MANUFACTURER = 716;
    private static final int TAG_ATTESTATION_ID_MODEL = 717;
    private static final int TAG_VENDOR_PATCHLEVEL = 718;
    private static final int TAG_BOOT_PATCHLEVEL = 719;
    private static final int TAG_MODULE_HASH = 724; // KeyMint 4.0+

    public static boolean canHack() {
        return !keyboxes.isEmpty();
    }

    /**
     * Parse a PEM-encoded private key. Supports both PEMKeyPair (traditional format)
     * and PKCS#8 PrivateKeyInfo (-----BEGIN PRIVATE KEY-----).
     */
    private static KeyPair parseKeyPair(String key) throws Throwable {
        String trimmed = UtilKt.trimLine(key);
        // Try full PEMKeyPair first
        try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair) {
                return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) obj);
            }
            // PKCS#8 — extract private key info, construct ephemeral KeyPair
            if (obj instanceof PrivateKeyInfo) {
                PrivateKey priv = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) obj);
                // Derive algorithm from OID
                return new KeyPair(null, priv);
            }
        }
        // Fallback: raw DER via PemReader for PKCS#8
        try (PemReader reader = new PemReader(new StringReader(trimmed))) {
            PemObject pem = reader.readPemObject();
            if (pem != null) {
                String type = pem.getType();
                if ("PRIVATE KEY".equals(type) || "RSA PRIVATE KEY".equals(type) || "EC PRIVATE KEY".equals(type)) {
                    PrivateKeyInfo info = PrivateKeyInfo.getInstance(pem.getContent());
                    PrivateKey priv = new JcaPEMKeyConverter().getPrivateKey(info);
                    return new KeyPair(null, priv);
                }
            }
        }
        throw new UnsupportedOperationException("Cannot parse private key: unsupported PEM format");
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(UtilKt.trimLine(cert)))) {
            return certificateFactory.generateCertificate(
                    new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }

    private static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }

    public static void readFromXml(String data) {
        keyboxes.clear();
        if (data == null) {
            Logger.i("clear all keyboxes");
            return;
        }
        XMLParser xmlParser = new XMLParser(data);

        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(
                    xmlParser.obtainPath("AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(
                        xmlParser.obtainPath(
                                "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates")
                                .get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();
                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String, String> certData = xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(parseCert(certData.get("text")));
                }
                String algo;
                if (keyboxAlgorithm.toLowerCase(Locale.ROOT).equals("ecdsa")) {
                    algo = KeyProperties.KEY_ALGORITHM_EC;
                } else {
                    algo = KeyProperties.KEY_ALGORITHM_RSA;
                }
                var kp = parseKeyPair(privateKey);
                keyboxes.put(algo, new KeyBox(kp, certificateChain));
            }
            Logger.i("update " + numberOfKeyboxes + " keyboxes");
        } catch (Throwable t) {
            Logger.e("Error loading xml file (keyboxes cleared): " + t);
        }
    }

    /**
     * 1.2.0-RC2: patch leaf certificate chain, fix security level, root of trust, and patch levels.
     * 1.3.0+: preserve moduleHash if present.
     * @param uid Android UID of the calling app (for applicationId resolution)
     */
    public static Certificate[] hackCertificateChain(Certificate[] caList, int uid) {
        if (caList == null) throw new UnsupportedOperationException("caList is null!");
        try {
            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(caList[0].getEncoded()));
            byte[] bytes = leaf.getExtensionValue(OID.getId());
            if (bytes == null) return caList;

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = leafHolder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();

            // Detect and fix swapped teeEnforced/softwareEnforced (some devices)
            // Normal: index 6 = softwareEnforced, index 7 = teeEnforced (with RoT)
            // Swapped: index 6 = teeEnforced (with RoT), index 7 = softwareEnforced
            ASN1Encodable candidateTee = encodables[7];
            ASN1Encodable candidateSw = encodables[6];
            boolean swapped = false;
            // Check if RoT (704) is in candidateSw (index 6) — if yes, sections are swapped
            if (candidateSw instanceof ASN1Sequence) {
                for (ASN1Encodable e : (ASN1Sequence) candidateSw) {
                    if (e instanceof ASN1TaggedObject && ((ASN1TaggedObject) e).getTagNo() == TAG_ROOT_OF_TRUST) {
                        swapped = true;
                        break;
                    }
                }
            }
            if (swapped) {
                // Swap sections back: index 6 ← original teeEnforced, index 7 ← original softwareEnforced
                encodables[6] = candidateTee; // now softwareEnforced
                encodables[7] = candidateSw;  // now teeEnforced
            }

            // 1.2.0-RC2: fix security levels to non-software
            encodables[1] = new ASN1Enumerated(1); // attestationSecurityLevel = TEE
            encodables[3] = new ASN1Enumerated(1); // keymasterSecurityLevel = TEE

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable rootOfTrust = null;
            boolean hasModuleHash = false;

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                if (!(asn1Encodable instanceof ASN1TaggedObject taggedObject)) {
                    vector.add(asn1Encodable);
                    continue;
                }
                if (taggedObject.getTagNo() == TAG_ROOT_OF_TRUST) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                if (taggedObject.getTagNo() == TAG_MODULE_HASH) {
                    hasModuleHash = true;
                    // preserve moduleHash from device
                    vector.add(taggedObject);
                    continue;
                }
                // Remove OS_VERSION, OS_PATCHLEVEL, VENDOR_PATCHLEVEL, BOOT_PATCHLEVEL
                // because they'll be replaced with config values
                if (taggedObject.getTagNo() == TAG_OS_VERSION ||
                        taggedObject.getTagNo() == TAG_OS_PATCHLEVEL ||
                        taggedObject.getTagNo() == TAG_VENDOR_PATCHLEVEL ||
                        taggedObject.getTagNo() == TAG_BOOT_PATCHLEVEL) {
                    continue;
                }
                vector.add(taggedObject);
            }

            var k = keyboxes.get(leaf.getPublicKey().getAlgorithm());
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + leaf.getPublicKey().getAlgorithm());

            LinkedList<Certificate> certificates = new LinkedList<>(k.certificates);
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(certificates.get(0).getEncoded()).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo());

            // Use normalized signature algorithm (1.1.2+)
            String sigAlg = normalizeSignatureAlgorithm(leaf.getSigAlgName());
            ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(k.keyPair.getPrivate());

            // Root of Trust
            byte[] verifiedBootKey = UtilKt.getBootKey();
            byte[] verifiedBootHash = UtilKt.getBootHash();
            try {
                if (rootOfTrust instanceof ASN1Sequence r) {
                    verifiedBootHash = getByteArrayFromAsn1(r.getObjectAt(3));
                }
            } catch (Throwable t) {
                Logger.e("failed to get boot hash from original, fallback to prop", t);
            }

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };
            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            vector.add(new DERTaggedObject(true, TAG_ROOT_OF_TRUST, hackedRootOfTrust));

            // 1.2.1+: OS version and patch levels from config
            vector.add(new DERTaggedObject(true, TAG_OS_VERSION,
                    new ASN1Integer(UtilKt.getOsVersion())));
            // Use uid from calling app for patch levels and applicationId
            vector.add(new DERTaggedObject(true, TAG_OS_PATCHLEVEL,
                    new ASN1Integer(UtilKt.getOsPatchLevel(uid))));
            vector.add(new DERTaggedObject(true, TAG_VENDOR_PATCHLEVEL,
                    new ASN1Integer(UtilKt.getVendorPatchLevel(uid))));
            vector.add(new DERTaggedObject(true, TAG_BOOT_PATCHLEVEL,
                    new ASN1Integer(UtilKt.getBootPatchLevel(uid))));

            // 1.3.0+: moduleHash from actual APEX modules (if not already present)
            if (!hasModuleHash) {
                vector.add(new DERTaggedObject(true, TAG_MODULE_HASH,
                        new DEROctetString(ModuleHash.INSTANCE.getValue())));
            }

            ASN1Sequence hackEnforced = new DERSequence(vector);
            encodables[7] = hackEnforced;

            // ATTESTATION_APPLICATION_ID (709) belongs in softwareEnforced (index 6),
            // not teeEnforced — matching generate path and KeyMint attestation layout.
            try {
                DEROctetString appId = createApplicationId(uid);
                if (appId != null) {
                    ASN1Sequence sw = (ASN1Sequence) encodables[6];
                    ASN1EncodableVector swVec = new ASN1EncodableVector();
                    for (ASN1Encodable e : sw) {
                        if (e instanceof ASN1TaggedObject t
                                && t.getTagNo() == TAG_APPLICATION_ID) {
                            continue; // replace existing
                        }
                        swVec.add(e);
                    }
                    swVec.add(new DERTaggedObject(true, TAG_APPLICATION_ID, appId));
                    encodables[6] = new DERSequence(swVec);
                }
            } catch (Throwable t) {
                Logger.e("failed to create application ID, skipping", t);
            }

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(leafHolder.getExtension(extensionOID));
            }
            certificates.addFirst(
                    new JcaX509CertificateConverter().getCertificate(builder.build(signer)));
            return certificates.toArray(new Certificate[0]);

        } catch (Throwable t) {
            Logger.e("hackCertificateChain failed", t);
        }
        return caList;
    }

    /**
     * 1.4.0+: generate full key pair with attested certificate chain. Wires KeyDb persistence.
     */
    public static Pair<KeyPair, List<Certificate>> generateKeyPair(
            int uid, KeyDescriptor descriptor, KeyGenParameters params) {
        Logger.i("Requested KeyPair with alias: " + descriptor.alias);
        try {
            KeyPair kp = null;
            KeyBox keyBox = null;
            var algo = params.algorithm;
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + params.keySize);
                kp = buildECKeyPair(params);
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + params.keySize);
                kp = buildRSAKeyPair(params);
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
            }
            if (keyBox == null || kp == null) {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }

            X500Name issuer = new X509CertificateHolder(
                    keyBox.certificates.get(0).getEncoded()).getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    params.certificateSerial,
                    params.certificateNotBefore,
                    params.certificateNotAfter,
                    params.certificateSubject,
                    kp.getPublic());

            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
            certBuilder.addExtension(createExtension(params, uid));

            // Select signature algorithm matching keybox key type
            String sigAlg = keyBox.keyPair.getPrivate().getAlgorithm().contains("EC")
                    ? "SHA256withECDSA" : "SHA256withRSA";
            ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg)
                    .build(keyBox.keyPair.getPrivate());

            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            var leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain = new ArrayList<>(keyBox.certificates);
            chain.add(0, leaf);

            Logger.d("Successfully generated attested key for alias: " + descriptor.alias);
            return new Pair<>(kp, chain);
        } catch (Throwable t) {
            Logger.e("generateKeyPair failed", t);
        }
        return null;
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(params.ecCurveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    /** Normalize signature algorithm name for Bouncy Castle (1.1.2+). */
    public static String normalizeSignatureAlgorithm(String algoName) {
        return algoName.toUpperCase(Locale.ROOT).replace("WITH", "with");
    }

    private static Extension createExtension(KeyGenParameters params, int uid) {
        try {
            byte[] key = UtilKt.getBootKey();
            byte[] hash = UtilKt.getBootHash();

            ASN1Encodable[] rootOfTrustEncodables = {
                    new DEROctetString(key),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(hash)
            };
            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            var Apurpose = new DERSet(fromIntList(params.purpose));
            var Aalgorithm = new ASN1Integer(params.algorithm);
            var AkeySize = new ASN1Integer(params.keySize);
            var Adigest = new DERSet(fromIntList(params.digest));
            var AecCurve = new ASN1Integer(params.ecCurve);
            var AnoAuthRequired = DERNull.INSTANCE;

            var AosVersion = new ASN1Integer(UtilKt.getOsVersion());
            var AosPatchLevel = new ASN1Integer(UtilKt.getOsPatchLevel(uid));
            var AapplicationID = createApplicationId(uid);
            var AbootPatchlevel = new ASN1Integer(UtilKt.getBootPatchLevel(uid));
            var AvendorPatchLevel = new ASN1Integer(UtilKt.getVendorPatchLevel(uid));
            var AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            var Aorigin = new ASN1Integer(0); // GENERATED
            var AmoduleHash = new DEROctetString(ModuleHash.INSTANCE.getValue());

            var purpose = new DERTaggedObject(true, 1, Apurpose);
            var algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            var keySize = new DERTaggedObject(true, 3, AkeySize);
            var digest = new DERTaggedObject(true, 5, Adigest);
            var ecCurve = new DERTaggedObject(true, 10, AecCurve);
            var noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            var creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            var origin = new DERTaggedObject(true, 702, Aorigin);
            var rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            var osVersion = new DERTaggedObject(true, 705, AosVersion);
            var osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);
            var applicationID = new DERTaggedObject(true, 709, AapplicationID);
            var vendorPatchLevel = new DERTaggedObject(true, 718, AvendorPatchLevel);
            var bootPatchLevel = new DERTaggedObject(true, 719, AbootPatchlevel);
            var moduleHash = new DERTaggedObject(true, 724, AmoduleHash);

            // Support device properties attestation (1.4.0)
            ASN1Encodable[] teeEnforcedEncodables;
            if (params.brand != null) {
                var Abrand = new DEROctetString(params.brand);
                var Adevice = new DEROctetString(params.device);
                var Aproduct = new DEROctetString(params.product);
                var Amanufacturer = new DEROctetString(params.manufacturer);
                var Amodel = new DEROctetString(params.model);
                var brand = new DERTaggedObject(true, 710, Abrand);
                var device = new DERTaggedObject(true, 711, Adevice);
                var product = new DERTaggedObject(true, 712, Aproduct);
                var manufacturer = new DERTaggedObject(true, 716, Amanufacturer);
                var model = new DERTaggedObject(true, 717, Amodel);

                teeEnforcedEncodables = new ASN1Encodable[]{
                        purpose, algorithm, keySize, digest, ecCurve,
                        noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel,
                        vendorPatchLevel, bootPatchLevel, moduleHash,
                        brand, device, product, manufacturer, model
                };
            } else {
                teeEnforcedEncodables = new ASN1Encodable[]{
                        purpose, algorithm, keySize, digest, ecCurve,
                        noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel,
                        vendorPatchLevel, bootPatchLevel, moduleHash
                };
            }

            // Software enforced: application ID + creation date
            ASN1Encodable[] softwareEnforced = {applicationID, creationDateTime};

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(
                    teeEnforcedEncodables, softwareEnforced, params);

            return new Extension(OID, false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Logger.e("createExtension failed", t);
        }
        return null;
    }

    private static ASN1OctetString getAsn1OctetString(
            ASN1Encodable[] teeEnforcedEncodables,
            ASN1Encodable[] softwareEnforcedEncodables,
            KeyGenParameters params) throws IOException {
        // KeyMint 4.0+ attestation version
        int attestVersion = UtilKt.getAttestVersion(1); // TEE security level
        ASN1Integer attestationVersion = new ASN1Integer(attestVersion);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1); // TEE
        ASN1Integer keymasterVersion = new ASN1Integer(UtilKt.getKeymasterVersion(1));
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1); // TEE
        ASN1OctetString attestationChallenge = new DEROctetString(
                params.attestationChallenge != null ? params.attestationChallenge : new byte[0]);
        ASN1OctetString uniqueId = new DEROctetString(new byte[0]);
        ASN1Encodable softwareEnforced = new DERSequence(softwareEnforcedEncodables);
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {
                attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId,
                softwareEnforced, teeEnforced
        };
        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);
        return new DEROctetString(keyDescriptionHackSeq);
    }

    private static DEROctetString createApplicationId(int uid) throws Throwable {
        var pm = Config.INSTANCE.getPm();
        if (pm == null) {
            Logger.w("createApplicationId: pm not found, skipping");
            return new DEROctetString(new DERSequence(new ASN1Encodable[0]).getEncoded());
        }
        var packages = pm.getPackagesForUid(uid);
        if (packages == null || packages.length == 0) {
            return new DEROctetString(new DERSequence(new ASN1Encodable[0]).getEncoded());
        }
        var size = packages.length;
        ASN1Encodable[] packageInfoAA = new ASN1Encodable[size];
        Set<Digest> signatures = new HashSet<>();
        var dg = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < size; i++) {
            var name = packages[i];
            var info = UtilKt.getPackageInfoCompat(pm, name, PackageManager.GET_SIGNATURES, uid / 100000);
            ASN1Encodable[] arr = new ASN1Encodable[2];
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                    new DEROctetString(packages[i].getBytes(StandardCharsets.UTF_8));
            arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(info.getLongVersionCode());
            packageInfoAA[i] = new DERSequence(arr);
            for (var s : info.signatures) {
                signatures.add(new Digest(dg.digest(s.toByteArray())));
            }
        }

        ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
        var i = 0;
        for (var d : signatures) {
            signaturesAA[i] = new DEROctetString(d.digest);
            i++;
        }

        ASN1Encodable[] applicationIdAA = new ASN1Encodable[2];
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] = new DERSet(packageInfoAA);
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] = new DERSet(signaturesAA);

        return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
    }

    record Digest(byte[] digest) {
        @Override
        public boolean equals(@Nullable Object o) {
            if (o instanceof Digest d)
                return Arrays.equals(digest, d.digest);
            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }

    record KeyBox(KeyPair keyPair, List<Certificate> certificates) {
    }

    public static class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Name certificateSubject;

        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;

        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();

        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;

        public KeyGenParameters(KeyParameter[] params) {
            for (var kp : params) {
                var p = kp.value;
                switch (kp.tag) {
                    case Tag.KEY_SIZE -> keySize = p.getInteger();
                    case Tag.ALGORITHM -> algorithm = p.getAlgorithm();
                    case Tag.CERTIFICATE_SERIAL ->
                            certificateSerial = new BigInteger(p.getBlob());
                    case Tag.CERTIFICATE_NOT_BEFORE ->
                            certificateNotBefore = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_NOT_AFTER ->
                            certificateNotAfter = new Date(p.getDateTime());
                    case Tag.CERTIFICATE_SUBJECT ->
                            certificateSubject = new X500Name(
                                    new X500Principal(p.getBlob()).getName());
                    case Tag.RSA_PUBLIC_EXPONENT ->
                            rsaPublicExponent = new BigInteger(p.getBlob());
                    case Tag.EC_CURVE -> {
                        ecCurve = p.getEcCurve();
                        ecCurveName = getEcCurveName(ecCurve);
                    }
                    case Tag.PURPOSE -> purpose.add(p.getKeyPurpose());
                    case Tag.DIGEST -> digest.add(p.getDigest());
                    case Tag.ATTESTATION_CHALLENGE -> attestationChallenge = p.getBlob();
                    case Tag.ATTESTATION_ID_BRAND -> brand = p.getBlob();
                    case Tag.ATTESTATION_ID_DEVICE -> device = p.getBlob();
                    case Tag.ATTESTATION_ID_PRODUCT -> product = p.getBlob();
                    case Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = p.getBlob();
                    case Tag.ATTESTATION_ID_MODEL -> model = p.getBlob();
                }
            }
        }

        private static String getEcCurveName(int curve) {
            return switch (curve) {
                case EcCurve.CURVE_25519 -> "CURVE_25519";
                case EcCurve.P_224 -> "secp224r1";
                case EcCurve.P_256 -> "secp256r1";
                case EcCurve.P_384 -> "secp384r1";
                case EcCurve.P_521 -> "secp521r1";
                default -> throw new IllegalArgumentException("unknown curve: " + curve);
            };
        }
    }
}