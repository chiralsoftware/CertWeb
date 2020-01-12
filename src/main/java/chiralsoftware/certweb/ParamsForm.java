package chiralsoftware.certweb;

import java.util.logging.Logger;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

/** 
 * A DTO for handling keystore parameters
 */
public class ParamsForm {

    private static final Logger LOG = Logger.getLogger(ParamsForm.class.getName());
    
    @NotNull
    @NotBlank
    private String domain;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain == null ? null : domain.trim();
    }

    @Override
    public String toString() {
        return "Params{" + "domain=" + domain + '}';
    }
    
    
    
}
