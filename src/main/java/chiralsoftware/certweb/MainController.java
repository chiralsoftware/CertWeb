package chiralsoftware.certweb;

import static chiralsoftware.certweb.CertificateUtilities.findCommonName;
import static chiralsoftware.certweb.CertificateUtilities.generateSelfSigned;
import static chiralsoftware.certweb.CertificateUtilities.isSelfSignedChain;
import static chiralsoftware.certweb.CertificateUtilities.verifyKey;
import chiralsoftware.certweb.dto.PrivateKeyEntryInfo;
import com.google.common.escape.Escaper;
import static com.google.common.io.BaseEncoding.base64;
import static com.google.common.xml.XmlEscapers.xmlAttributeEscaper;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import java.util.logging.Logger;
import static java.util.stream.Collectors.toUnmodifiableList;
import javax.naming.InvalidNameException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import static org.bouncycastle.asn1.x509.GeneralName.dNSName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import org.springframework.http.ResponseEntity;
import static org.springframework.http.ResponseEntity.notFound;
import static org.springframework.http.ResponseEntity.ok;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Possible future enhancement: use this library: https://pkijs.org/#examples to
 * show info about certs dynamically Or use this:
 * https://www.npmjs.com/package/x509 which might be simpler
 *
 * THE GOAL We want to create a P12 store that has a single entry with alias
 * "tomcat" That entry is a PrivateKeyEntry type Obviously it has a private key
 * It also has a certificate chain, with chain[0] issuer=intermediate cert,
 * subject=our domain name chain[1] issuer=root cert, subject=intermediate cert
 */
@Controller
public class MainController {

    private static final Logger LOG = Logger.getLogger(MainController.class.getName());

    @Value("${keystore.file:/opt/zombiecam/jetty-base/etc/keystore}")
    private String keystoreFileName;

    @Value("${keystore.password:changeit}")
    public void setKeyStorePassword(String s) {
        keystorePassword = s;
        keystorePasswordChars = s.toCharArray();
        passwordProtection = new PasswordProtection(keystorePasswordChars);
    }
    private String keystorePassword;

    private char[] keystorePasswordChars;
    private PasswordProtection passwordProtection;

    @Value("${keystore.alias:tomcat}")
    private String keystoreAlias;

    @Autowired
    private ShutdownService shutdownService;

    @GetMapping("/")
    public String index(Model model) {
        final List<Message> messages = new ArrayList();
        model.addAttribute("status", messages);

        // we should add smoe error checking, so if the keystore exists
        // but should be reset, we can do that
        final File keystoreFile = new File(keystoreFileName);
        if (keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file exists"));
            // find out if there is a chain saved or not
            try {
                final KeyStore store = loadKeyStore();
                if (!store.entryInstanceOf(keystoreAlias, PrivateKeyEntry.class)) {
                    LOG.info("Keystore doesn't have a private key entry so this isn't valid.");
                    return "redirect:step-1";
                }
                // it has a private key entry - is it a chain or self-signed cert?
                if (isSelfSignedChain(((PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection)).getCertificateChain())) {
                    LOG.info("Keystore has a private key entry and it is self-signed so it's time for CSR action");
                    return "redirect:step-2";
                }
            } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
                LOG.log(WARNING, "couldn't load the keystore", ex);
                messages.add(new Message(WARNING, "couldn't access keystore file: " + keystoreFileName + " due to: " + ex.getMessage()));
                return "redirect:broken";
            }
            // we have a full chain in there so go to step 3 to let the user view it
            return "redirect:step-3";
        } else {
            messages.add(new Message(INFO, "Please initialize keystore"));
            return "redirect:step-1";
        }
    }

    @PostMapping(value = "/reset-keystore")
    public String resetKeystore(RedirectAttributes model) {
        LOG.info("Resetting the keystore and going back to step 1");
        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);

        final File keystoreFile = new File(keystoreFileName);
        if (keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile
                    + " exists, and will be erased and re-created."));
            final boolean result = keystoreFile.delete();
            if (result) {
                messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " deleted."));
            } else {
                messages.add(new Message(WARNING, "Keystore file: " + keystoreFile + " could not be deleted"));
            }
        } else {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " did not exist so it will be created."));
        }
        return "redirect:step-1";
    }

    @GetMapping(value = "/step-1")
    public String step1(Model model, HttpServletRequest request) {
        final List<Message> messages = new ArrayList();
        model.addAttribute("status", messages);
        final File keystoreFile = new File(keystoreFileName);
        if (keystoreFile.exists()) {
            // this shouldn't happen - FIXME make it test that if the keystore exists, it has a private key
            LOG.log(INFO, "Keystore file: " + keystoreFile + " exists. Generating CSR.");
            return "redirect:step-2";
        } else {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " does not exist, and will be created"));
        }
        final ParamsForm paramsForm = new ParamsForm();

        try {
            final String hostName = new URL(request.getRequestURL().toString()).getHost();
            if("localhost".equalsIgnoreCase(hostName)) 
                LOG.fine("The detected hostname is localhost, so not setting it in the form.");
            else 
                paramsForm.setDomain(hostName);
            LOG.info("Detected hostname: " + hostName);
        } catch (MalformedURLException ex) {
            LOG.log(WARNING, "couldn't parse the URL: " + request.getRequestURL(), ex);
            return "redirect:broken";
        }
        model.addAttribute("paramsForm", paramsForm);
        return "step-1";
    }

    @PostMapping(value = "/create-private-key")
    public String createPrivateKey(@ModelAttribute @Valid ParamsForm paramsForm, BindingResult bindingResult, RedirectAttributes model) {
        LOG.info("Resetting everything!");
        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);
        final KeyStore store;
        try {
            store = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException ex) {
            LOG.log(INFO, "couldn't create keystore", ex);
            messages.add(new Message(SEVERE, "could not create keystore of type PKCS12"));
            return "redirect:broken";
        }

        final File keystoreFile = new File(keystoreFileName);
        if (keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " exists, deleting it"));
            final boolean result = keystoreFile.delete();
            if (!result) {
                messages.add(new Message(WARNING, "Keystore file: " + keystoreFile + " could not be deleted"));
                return "redirect:broken";
            }
        }

        messages.add(new Message(INFO, "Generating key pair"));
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);

            final KeyPair pair = keyGen.generateKeyPair();
            if (paramsForm.getDomain() == null || paramsForm.getDomain().isBlank()) {
                LOG.severe("The domain was blank! this isn't going to work!");
            }
            final X509Certificate selfSigned = generateSelfSigned(paramsForm.getDomain(), pair);
            store.load(null, null);
            store.setEntry(keystoreAlias,
                    new PrivateKeyEntry(pair.getPrivate(), new Certificate[]{selfSigned}),
                    passwordProtection);
            store.store(new FileOutputStream(keystoreFile), keystorePassword.toCharArray());
            LOG.info("Keystore file was saved!");
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " saved with private key entry."));
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException
                | CertificateException | OperatorCreationException ex) {
            LOG.log(SEVERE, "couldn't generate keypair", ex);
            messages.add(new Message(SEVERE, "Caught exception while generating key pair: " + ex.getMessage()));
            return "redirect:broken";
        }
        return "redirect:step-2";
    }

    private String csrString = null;
    private String csrName = null;

    @GetMapping("/step-2")
    public String step2get(Model model) {
        final List<Message> status = new ArrayList<>();
        model.addAttribute("status", status);
        // should be able to load the store
        final KeyStore store;
        try {
            store = loadKeyStore();
            status.add(new Message(INFO, "KeyStore loaded from file: " + keystoreFileName));
            final Entry entry = store.getEntry(keystoreAlias, passwordProtection);
            if (!(entry instanceof PrivateKeyEntry)) {
                status.add(new Message(WARNING, "The keystore entry with alias: " + keystoreAlias + " was not a PrivateKeyEntry"));
                return "redirect:broken";
            }
            final PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) entry;

            // see: https://stackoverflow.com/questions/7933468/parsing-the-cn-out-of-a-certificate-dn
            final String commonName = findCommonName(((X509Certificate) privateKeyEntry.getCertificate()));

            if (commonName.equalsIgnoreCase("null")) {
                LOG.severe("The subject name was NULL! The certificate was not generated properly.");
                return "redirect:broken";
            }
            status.add(new Message(INFO, "Generating CSR from key and self-signed certificate, "
                    + "with common name =" + commonName));

            final PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    ((X509Certificate) privateKeyEntry.getCertificate()).getSubjectX500Principal(),
                    privateKeyEntry.getCertificate().getPublicKey());

            // Chrome requires Subject Alternative Names to work
            // see this SO: https://stackoverflow.com/questions/34169954/create-pkcs10-request-with-subject-alternatives-using-bouncy-castle-in-java
            final ExtensionsGenerator extGen = new ExtensionsGenerator();

            final GeneralNames subjectAltNames
                    = new GeneralNames(new GeneralName[]{new GeneralName(dNSName, commonName)});
            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

            final JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            final ContentSigner signer = csBuilder.build(privateKeyEntry.getPrivateKey());
            final PKCS10CertificationRequest csr = p10Builder.build(signer);
            csrString
                    = "-----BEGIN CERTIFICATE REQUEST-----\n"
                    + base64().withSeparator("\n", 80).encode(csr.getEncoded()) + "\n"
                    + "-----END CERTIFICATE REQUEST-----\n";

            model.addAttribute("csr", csrString);
            csrName = commonName;
            // for testing:
//            Files.write(csrString.getBytes(), new File("/tmp/csr.pem"));
            // and then : openssl req -in /tmp/csr.pem -noout -text
        } catch (CertificateException | IOException | NoSuchAlgorithmException
                | KeyStoreException | UnrecoverableEntryException
                | OperatorCreationException | InvalidNameException ex) {
            LOG.log(INFO, "oh no!", ex);
            status.add(new Message(WARNING, "couldn't create CSR: " + ex.getMessage()));
        }
        return "step-2";
    }

    @PostMapping("/save-response")
    public String uploadFullchain(@RequestParam MultipartFile fullchain, RedirectAttributes model) throws IOException, CertificateException {

        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);

        final List<X509Certificate> certificates = CertificateFactory.
                getInstance("X.509").generateCertificates(fullchain.getInputStream()).
                stream().map(c -> (X509Certificate) c).collect(toUnmodifiableList());
        if (certificates.isEmpty()) {
            messages.add(new Message(WARNING, "The uploaded chain was empty"));
            return "redirect:step-2";
        }

        try {
            final KeyStore store = loadKeyStore();
            final PrivateKeyEntry pke
                    = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);

            // at this point, the PrivateKeyEntry should have exactly one cert which should be self-signed
            // and the subject should be the same as the subject of the uploaded chain[0]. 
            // Question 1: do the Subjects match?
            if (!((X509Certificate) pke.getCertificate()).getSubjectX500Principal().equals(certificates.get(0).getSubjectX500Principal())) {
                messages.add(new Message(SEVERE, "the first certificate in the uploaded chain subject does not match the domain"));
                return "redirect:step-2";
            }
            // Question 2: does the private key match the public key in chain[0]?
            if (!verifyKey(pke.getPrivateKey(), certificates.get(0))) {
                messages.add(new Message(SEVERE, "the public key in the signed certificate does not match the private key."));
                return "redirect:step-2";
            }

            // check for errors
            // first does the cert[0] subject public key match the private key
            if (certificates.size() < 2) {
                messages.add(new Message(WARNING, "The chain you uploaded contained less than two certificates. "
                        + "Typically a chain has an entity certificate and an intermediate certificate. "
                        + "This probably isn't the full chain file."));
            }
            // at this point we should attach the chain and save it
            final PrivateKeyEntry newEntry = new PrivateKeyEntry(pke.getPrivateKey(),
                    certificates.toArray(new Certificate[0]));
            store.setEntry(keystoreAlias, newEntry, passwordProtection);
            store.store(new FileOutputStream(keystoreFileName), keystorePasswordChars);
            messages.add(new Message(INFO, "Key store has been saved to : " + keystoreFileName));
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException
                | UnrecoverableEntryException ex) {
            LOG.log(WARNING, "oh no", ex);
            messages.add(new Message(SEVERE, "couldn't store the response: " + ex.getMessage()));
            return "redirect:broken";
        }
        return "redirect:step-3";
    }

    /**
     * The purpose of this method is to remove the chain from a store. In other
     * words, we go back from step-3 (the end step) to step-2. One reason users
     * might want to do this is to update the signed certificate with a new
     * expiration time, or if the user has decided to switch to a different root
     * CA. This is also helpful in testing. This does nothing if there already
     * is no chain, ie certificate[0] is self-signed
     */
    @PostMapping("/remove-chain")
    public String removeChain(RedirectAttributes model) {
        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);
        LOG.info("attempting to remove the chain from the keystore.");
        try {
            final KeyStore store = loadKeyStore();
            if (!store.entryInstanceOf(keystoreAlias, PrivateKeyEntry.class)) {
                messages.add(new Message(WARNING, "keystore didn't contain PrivateKeyEntry "
                        + "for alias " + keystoreAlias + ", returning to step 1"));
            }
            final PrivateKeyEntry pke = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);
            // we need to re-generate teh self-signed cert!
            final X509Certificate cert = (X509Certificate) pke.getCertificate();
            final X509Certificate selfSigned
                    = generateSelfSigned(findCommonName(cert),
                            new KeyPair(cert.getPublicKey(), pke.getPrivateKey()));
            final PrivateKeyEntry newPke = new PrivateKeyEntry(pke.getPrivateKey(), new Certificate[]{selfSigned});
            store.setEntry(keystoreAlias, newPke, passwordProtection);
            store.store(new FileOutputStream(keystoreFileName), keystorePasswordChars);
            messages.add(new Message(INFO, "Chain removed from keystore"));
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException
                | UnrecoverableEntryException | OperatorCreationException | InvalidNameException ex) {
            LOG.log(WARNING, "oh no!", ex);
            messages.add(new Message(WARNING, "keystore couldn't load due to: " + ex.getMessage()));
            return "redirect:broken";
        }

        return "redirect:step-2";
    }

    @GetMapping("/csr")
    public ResponseEntity<byte[]> downloadCsrString() {

        if (csrString == null) {
            LOG.warning("Attempting to download CSR string but it is null!");
            return notFound().build();
        }
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.
                builder("attachment").filename(csrName + ".csr").build());
        headers.setContentType(TEXT_PLAIN);
        return ok().headers(headers).body(csrString.getBytes());
    }

    @GetMapping("/step-3")
    public String step3get(Model model) {
        final List<Message> status = new ArrayList<>();
        model.addAttribute("status", status);
        // should be able to load the store
        final KeyStore store;
        try {
            store = loadKeyStore();
            final PrivateKeyEntry pke = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);
            final Escaper xmlAttributeEscaper = xmlAttributeEscaper();
            final String connector = "<Connector port=\"443\" protocol=\"org.apache.coyote.http11.Http11NioProtocol\"\n"
                    + "           keystoreFile=\"" + xmlAttributeEscaper.escape(keystoreFileName) + "\"\n"
                    + "           SSLProtocol=\"TLSv1.3,TLSv1.2\" SSLEnabled=\"true\"\n"
                    + "           keystorePass=\"" + xmlAttributeEscaper.escape(keystorePassword)
                    + "\" keyAlias=\"" + xmlAttributeEscaper.escape(keystoreAlias) + "\">\n"
                    + "  <UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\"/>\n"
                    + "</Connector>";
            model.addAttribute("privateKeyEntry", new PrivateKeyEntryInfo(pke));
            model.addAttribute("connector", connector);
        } catch (CertificateException | IOException
                | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            LOG.log(WARNING, "oh no!", ex);
        }
        return "step-3";
    }

    /**
     * Load the keystore with the given parameters
     */
    private KeyStore loadKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        final KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new FileInputStream(keystoreFileName), keystorePassword.toCharArray());
        return store;
    }

    @GetMapping("/broken")
    public String broken() {
        return "broken";
    }

    @GetMapping("/shutdown")
    public String shutdownGet() {
        return "shutdown";
    }

    @PostMapping("/shutdown")
    public String shutdown() throws InterruptedException {
        LOG.info("Shutdown requested");
        shutdownService.shutdown();
        LOG.info("Async task has started!");
        return "redirect:shutdown";
    }

}
