package chiralsoftware.certweb;

import static chiralsoftware.certweb.CertificateUtilities.generateSelfSigned;
import static chiralsoftware.certweb.CertificateUtilities.isSelfSignedChain;
import chiralsoftware.certweb.dto.PrivateKeyEntryInfo;
import static com.google.common.io.BaseEncoding.base64;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;
import static java.util.logging.Level.WARNING;
import java.util.logging.Logger;
import static java.util.stream.Collectors.toUnmodifiableList;
import javax.security.auth.x500.X500Principal;
import javax.validation.Valid;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
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
 * Possible future enhancement:
 * use this library: https://pkijs.org/#examples to show info about certs dynamically
 * Or use this: https://www.npmjs.com/package/x509 which might be simpler
 * 
 * THE GOAL
 * We want to create a P12 store that has a single entry with alias "tomcat"
 * That entry is a PrivateKeyEntry type
 * Obviously it has a private key
 * It also has a certificate chain, with chain[0] issuer=intermediate cert, subject=our domain name
 *                                       chain[1] issuer=root cert, subject=intermediate cert
 *             NOT NEEDED!!!!!           chain[2] issuer=root cert, subject=root cert ?
 */
@Controller
public class MainController {

    private static final Logger LOG = Logger.getLogger(MainController.class.getName());
    
    @Value("${keystore.file:/etc/zombiecam/certificates.p12}")
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
    
    static {
        //do we actually need to do this, now that the pkcs12 is the standard keystore?
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            // insert at specific position
//            LOG.info("Adding BouncyCastleProvider");
//            Security.addProvider(new BouncyCastleProvider());
        }

    }
    
    @GetMapping("/")
    public String index(Model model) throws KeyStoreException, IOException, 
            NoSuchAlgorithmException, CertificateException, NoSuchProviderException, UnrecoverableEntryException {
        LOG.info("Getting the index, using file: " + keystoreFileName + " and password: " + keystorePassword);
        // see:
        // https://github.com/bcgit/bc-java/blob/master/misc/src/main/java/org/bouncycastle/jcajce/examples/PKCS12Example.java
        final List<Message> messages = new ArrayList();
        model.addAttribute("status", messages);

        // we should add smoe error checking, so if the keystore exists
        // but should be reset, we can do that
        final File keystoreFile = new File(keystoreFileName);
        if(keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file exists"));
            // find out if there is a chain saved or not
            final KeyStore store = loadKeyStore();
            if(! store.entryInstanceOf(keystoreAlias, PrivateKeyEntry.class)) {
                LOG.info("Keystore doesn't have a private key entry so this isn't valid.");
                return "redirect:/step-1";
            }
            // it has a private key entry - is it a chain or self-signed cert?
            if(isSelfSignedChain(((PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection)).getCertificateChain())) {
                 LOG.info("Keystore has a private key entry and it is self-signed so it's time for CSR action");
                 return "redirect:/step-2";
            }
            // we have a full chain in there so go to step 3 to let the user view it
            return "redirect:/step-3";
        } else {
            messages.add(new Message(INFO, "Please initialize keystore"));
            return "redirect:/step-1";
        }
    }
    
    @PostMapping(value="/reset-keystore")
    public String resetKeystore(RedirectAttributes model) {
        LOG.info("Resetting the keystore and going back to step 1");
        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);
        
        final File keystoreFile = new File(keystoreFileName);
        if(keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + 
                " exists, and will be erased and re-created."));
            final boolean result = keystoreFile.delete();
            if(result)
                messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " deleted."));
            else
                messages.add(new Message(WARNING, "Keystore file: " + keystoreFile + " could not be deleted"));
        } else {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " did not exist so it will be created."));
        }
        return "redirect:/step-1";
    }
    
    @GetMapping(value="/step-1")
    public String step1(Model model) {
        final List<Message> messages = new ArrayList();
        model.addAttribute("status", messages);
        final File keystoreFile = new File(keystoreFileName);
        if(keystoreFile.exists()) {
            // this shouldn't happen - FIXME make it test that if the keystore exists, it has a private key
           LOG.log(INFO, "Keystore file: " + keystoreFile +  " exists. Generating CSR.");
           return "redirect:/step-2";
        } else {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " does not exist, and will be created"));
        }
        model.addAttribute("paramsForm", new ParamsForm());
        return "/step-1";
    }
    
    @PostMapping(value="/create-private-key")
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
            return "redirect:/";
        }
        
        final File keystoreFile = new File(keystoreFileName);
        if(keystoreFile.exists()) {
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " exists, deleting it"));
            final boolean result = keystoreFile.delete();
            if(! result) {
                messages.add(new Message(WARNING, "Keystore file: " + keystoreFile + " could not be deleted"));
            }
        }
//        if(! keystoreFile.canWrite()) {
//           messages.add(new Message(SEVERE, "Cannot access file: " + keystoreFile + " for writing"));
//           return "redirect:/";
//        }
        // now generating a key
        messages.add(new Message(INFO, "Generating key pair"));
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);

            final KeyPair pair = keyGen.generateKeyPair();
            if(paramsForm.getDomain() == null || paramsForm.getDomain().isBlank()) {
                LOG.severe("The domain was blank! this isn't going to work!");
            }
            final X509Certificate selfSigned = generateSelfSigned(paramsForm.getDomain(), pair);
            store.load(null, null);
            store.setEntry(keystoreAlias, 
                    new PrivateKeyEntry(pair.getPrivate(), new Certificate[] { selfSigned }), 
                    new PasswordProtection(keystorePassword.toCharArray()));
            store.store(new FileOutputStream(keystoreFile), keystorePassword.toCharArray());
            LOG.info("Keystore file was saved!");
            messages.add(new Message(INFO, "Keystore file: " + keystoreFile + " saved with private key entry."));
        } catch(NoSuchAlgorithmException | KeyStoreException | IOException | 
                CertificateException | OperatorCreationException ex) {
            LOG.log(SEVERE, "couldn't generate keypair", ex);
        }
        return "redirect:/step-2";
    }
    
    private String csrString = null;
    
    @GetMapping("/step-2")
    public String step2get(Model model) {
        final List<Message> status = new ArrayList<>();
        model.addAttribute("status", status);
        // should be able to load the store
        final KeyStore store ;
        try {
            store = loadKeyStore();
            status.add(new Message(INFO, "KeyStore loaded from file: " + keystoreFileName));
            final Entry entry = store.getEntry(keystoreAlias, new PasswordProtection(keystorePassword.toCharArray()));
            if(! (entry instanceof PrivateKeyEntry)) {
                // this shoudl go back to step 1
                return "redirect:/";
            }
            final PrivateKeyEntry privateKeyEntry  = (PrivateKeyEntry) entry;
            
            final X500Principal subject = ((X509Certificate) privateKeyEntry.getCertificate()).getSubjectX500Principal();
            if(subject.getName().endsWith("=null")) {
                LOG.severe("The subject name was NULL! The certificate was not generated properly.");
            }
            status.add(new Message(INFO, "Generating CSR from key and self-signed certificate, "
                    + "with subject=" + subject));
            
            final PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                ((X509Certificate) privateKeyEntry.getCertificate()).getSubjectX500Principal(), 
                    privateKeyEntry.getCertificate().getPublicKey());
            
            final JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
            final ContentSigner signer = csBuilder.build(privateKeyEntry.getPrivateKey());
            final PKCS10CertificationRequest csr = p10Builder.build(signer);
            csrString
                = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + base64().withSeparator("\n", 80).encode(csr.getEncoded()) + "\n"
                + "-----END CERTIFICATE REQUEST-----\n";

            model.addAttribute("csr", csrString);
            // for testing:
//            Files.write(csrString.getBytes(), new File("/tmp/csr.pem"));
            // and then : openssl req -in /tmp/csr.pem -noout -text
        } catch(CertificateException | IOException | NoSuchAlgorithmException | 
                KeyStoreException | UnrecoverableEntryException | OperatorCreationException ex) {
            LOG.log(INFO, "oh no!", ex);
        }
        return "/step-2";
    }
    
    private KeyStore loadKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(keystoreFileName), keystorePassword.toCharArray());
            return store;
    }
    
    @PostMapping("/save-response")
    public String uploadFullchain(@RequestParam MultipartFile fullchain, RedirectAttributes model) throws IOException, CertificateException {

        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);

        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final Collection<? extends Certificate> certs =  certificateFactory.generateCertificates(fullchain.getInputStream());
        final List<X509Certificate> certificates = certs.stream().
                map(c ->  { return (X509Certificate) c; }).
        collect(toUnmodifiableList());
        final KeyStore store;
        try {
            store = loadKeyStore();
            final PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);
            // check for errors
            // first does the cert[0] subject public key match the private key

            if(certificates.size() < 2) {
                messages.add(new Message(WARNING, "The chain you uploaded contained less than two certificates. "
                        + "Typically a chain has an entity certificate and an intermediate certificate. "
                        + "This probably isn't the full chain file."));
            }
            // at this point we should attach the chain and save it
            final PrivateKeyEntry newEntry = new PrivateKeyEntry(privateKeyEntry.getPrivateKey(), 
                    certificates.toArray(new Certificate[0]));
            store.setEntry(keystoreAlias, newEntry, new PasswordProtection(keystorePassword.toCharArray()));
            store.store(new FileOutputStream(keystoreFileName), keystorePassword.toCharArray());
            messages.add(new Message(INFO, "Key store has been saved to : "  + keystoreFileName));
        } catch(CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException |
                UnrecoverableEntryException ex) {
            LOG.log(WARNING, "oh no", ex);
        }
        return "redirect:/step-3";
    }
    
    /** The purpose of this method is to remove the chain from a store.
     In other words, we go back from step-3 (the end step) to step-2.
     One reason users might want to do this is to update the signed certificate
     with a new expiration time, or if the user has decided to switch to a different
     root CA. This is also helpful in testing. 
     This does nothing if there already is no chain, ie certificate[0] is self-signed */
    @PostMapping("/remove-chain")
    public String removeChain(RedirectAttributes model) {
        final List<Message> messages = new ArrayList<>();
        model.addFlashAttribute("messages", messages);
        LOG.info("attempting to remove the chain from the keystore.");
        try {
            final KeyStore store = loadKeyStore();
            if(! store.entryInstanceOf(keystoreAlias, PrivateKeyEntry.class)) {
                messages.add(new Message(WARNING, "keystore didn't contain PrivateKeyEntry "
                        + "for alias " + keystoreAlias + ", returning to step 1"));
            }
            final PrivateKeyEntry pke = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);
            // we need to re-generate teh self-signed cert!
            final X509Certificate cert = (X509Certificate) pke.getCertificate();
            final X509Certificate selfSigned =
                    generateSelfSigned(cert.getSubjectDN().getName().replace("cn=", ""),
                            new KeyPair(cert.getPublicKey(), pke.getPrivateKey()));
            final PrivateKeyEntry newPke = new PrivateKeyEntry(pke.getPrivateKey(), new Certificate[] { selfSigned });
            store.setEntry(keystoreAlias, newPke, passwordProtection);
            store.store(new FileOutputStream(keystoreFileName), keystorePasswordChars);
            messages.add(new Message(INFO, "Chain removed from keystore"));
        } catch(CertificateException | IOException | KeyStoreException | 
                NoSuchAlgorithmException | UnrecoverableEntryException |
                OperatorCreationException ex) {
            LOG.log(WARNING, "oh no!", ex);
            messages.add(new Message(WARNING, "keystore couldn't load, returning to step 1"));
            return "redirect:/step-1";
        }
        
        return "redirect:/step-2";
    }
    
    @GetMapping("/csr")
    public ResponseEntity<byte[]> downloadCsrString() {
        
        if(csrString == null) {
            LOG.warning("Attempting to download CSR string but it is null!");
            return notFound().build();
        }
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.builder("attachment").filename("csr.pem").
                        creationDate(ZonedDateTime.now()).build());
        headers.setContentType(TEXT_PLAIN);
        return ok().headers(headers).body(csrString.getBytes());
    }
    
    @GetMapping("/step-3")
    public String step3get(Model model) {
        final List<Message> status = new ArrayList<>();
        model.addAttribute("status", status);
        // should be able to load the store
        final KeyStore store ;
        try { 
            store = loadKeyStore();
            final PrivateKeyEntry pke = (PrivateKeyEntry) store.getEntry(keystoreAlias, passwordProtection);
            model.addAttribute("privateKeyEntry", new PrivateKeyEntryInfo(pke));
        } catch(CertificateException | IOException | 
                KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            LOG.log(WARNING, "oh no!", ex);
        }
        return "/step-3";
    }
    
    // we shoudl be able to fix file permissions before exiting!
    // https://stackoverflow.com/questions/13241967/change-file-owner-group-under-linux-with-java-nio-files
    
}
