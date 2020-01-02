package chiralsoftware.certweb;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import static java.util.logging.Level.INFO;
import java.util.logging.Logger;

/**
 * Hold information about the state of the key store
 */
public enum KeyStoreState {
    
    UNINITIALIZED, SELFSIGNED, CHAIN, BROKEN;

    private static final Logger LOG = Logger.getLogger(KeyStoreState.class.getName());

    /** Determine the state of the key store */
    public static KeyStoreState findState(KeyStore keyStore,  String alias, ProtectionParameter protection) {
        if(keyStore == null) return UNINITIALIZED;
        try {
            if(! keyStore.entryInstanceOf(alias, PrivateKeyEntry.class)) return UNINITIALIZED;
        } catch (KeyStoreException ex) {
            LOG.log(INFO, "couldn't access key store", ex);
            return BROKEN;
        }
        
        return null;
    }
    
}
