package chiralsoftware.certweb;

import static java.lang.System.exit;
import static java.lang.Thread.sleep;
import java.util.logging.Logger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * A service to asynchronously shut down the server so the user can exit
 */
@Service
public class ShutdownService {

    private static final Logger LOG = Logger.getLogger(ShutdownService.class.getName());
    
    /** Time to wait in seconds. This is to allow the browser to display the
     shutdown page successfully. */
    private static final int delay = 3;
    
    @Async
    public void shutdown() throws InterruptedException {
        LOG.info("Shutdown requested, sleeping " + delay + " seconds");
        sleep(delay * 1000);
        LOG.info("About to shut down the VM");
        exit(0);
    }
    
}
