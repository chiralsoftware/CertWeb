package chiralsoftware.certweb;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class CertWebApplication {

    public static void main(String[] args) {
        SpringApplication.run(CertWebApplication.class, args);
    }
    
    // We don't define an Executor bean, because we only need
    // the executor to do one thing so the default SimpleAsyncTaskExecutor
    // is fine

}
