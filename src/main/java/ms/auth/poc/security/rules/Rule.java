package ms.auth.poc.security.rules;

import ms.auth.poc.security.exceptions.RuleViolationException;

public interface Rule {
    public void execute() throws RuleViolationException;
}
