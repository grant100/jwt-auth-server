package ms.auth.poc.security.exceptions;

public class RuleViolationException extends RuntimeException {
    public RuleViolationException(String msg){
        super(msg);
    }

    public RuleViolationException(String msg, Exception e){
        super(msg, e);
    }
}
