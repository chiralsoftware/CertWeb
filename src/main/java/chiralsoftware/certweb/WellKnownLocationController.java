package chiralsoftware.certweb;

import static com.google.common.base.Ascii.truncate;
import com.google.common.collect.EvictingQueue;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import static java.lang.Integer.min;
import java.time.Instant;
import static java.time.Instant.now;
import java.util.logging.Logger;
import static org.apache.commons.lang3.ArrayUtils.reverse;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import static org.springframework.http.HttpHeaders.USER_AGENT;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import org.springframework.http.ResponseEntity;
import static org.springframework.http.ResponseEntity.notFound;
import static org.springframework.http.ResponseEntity.ok;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.multipart.MultipartFile;

/**
 * Key authorities often require a small file to be placed at a well-known location to validate
 * a domain. This controller is for that purpose.
 * This often is a URL like:
 * http://example.com/.well-known/pki-validation/godaddy.html
 */
@Controller
public class WellKnownLocationController {

    private static final Logger LOG = Logger.getLogger(WellKnownLocationController.class.getName());
    
    private String wellKnownPath = null;
    private byte[] fileValue = "this is the file bytes".getBytes();
    
    private static record Request(String path, String url, String ipAddress, String userAgent, short responseCode, Instant time) { 
        static Request build(HttpServletRequest r, short responseCode) {
            return new Request(truncate(r.getRequestURI(),80, "..."), 
                    truncate(r.getRequestURL().toString(),120, "..."),
                    r.getRemoteAddr(), truncate(r.getHeader(USER_AGENT),50, "..."), 
                    responseCode, now());
        }
    }
    private final EvictingQueue<Request> requests = EvictingQueue.create(20);
    
    private static String fileToString(byte[] bytes) {
        final StringBuilder result = new StringBuilder();
        for(int i = 0; i < min(bytes.length, 100); i++)
            if(Character.isAlphabetic(bytes[i]) || bytes[i] == ' ') result.append((char)bytes[i]);
        return result.toString();
    }
    
    @GetMapping("/.well-known")
    public String getForm(HttpServletRequest request, Model model) {
        final Request[] requestArray = new Request[requests.size()];
        requests.toArray(requestArray);
        reverse(requestArray);
        model.addAttribute("requests", requestArray);
        model.addAttribute("wellKnownPath", wellKnownPath);
        model.addAttribute("file", fileToString(fileValue));
        model.addAttribute("requestUrl", request.getRequestURL().toString());
        
        return "well-known";
    }
    
    @GetMapping("/.well-known/**")
    public ResponseEntity<Resource> getFile(HttpServletRequest request) {
        
        if(wellKnownPath == null || fileValue == null) {
            requests.add(Request.build(request, (short) NOT_FOUND.value()));
            return notFound().build();
        }
        final String context = request.getContextPath();
        final String requestUri = request.getRequestURI();
        final String path = requestUri.startsWith(context) ? requestUri.substring(context.length()) : requestUri;
        String subPath = path.substring("/.well-known".length());
        if(subPath.startsWith("/")) subPath = subPath.substring(1);
        if(!subPath.equals(wellKnownPath)) {
            LOG.finest("subPath: " + subPath + " does not equal to wellKnownPath: " + wellKnownPath);
            requests.add(Request.build(request, (short) NOT_FOUND.value()));
            return notFound().build();
        }
        requests.add(Request.build(request, (short) OK.value()));
        return ok().contentType(TEXT_PLAIN).
                contentLength(fileValue.length).body(new ByteArrayResource(fileValue));
    }
    
    @PostMapping("/.well-known")
    public String post(MultipartFile contents, String path) throws IOException {
        wellKnownPath = truncate(path.trim(),100, "..."); 
        if(wellKnownPath.startsWith("/")) wellKnownPath = wellKnownPath.substring(1);
        if(contents.getSize() > 8096) LOG.warning("The uploaded file was too large");
        fileValue = contents.getBytes();
        LOG.finest("this is now the path: " + wellKnownPath + " and the file bytes are: " + fileToString(fileValue));
        return "redirect:/.well-known";
    }
    
}
