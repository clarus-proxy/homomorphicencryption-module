package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.Criteria;

public class HomomorphicCriteria extends Criteria {
    // This implementation is only intended to limit the supported operations
    // over homomophically encrypted values.
    // The constructor is private, but is provides a factory interface.
    private HomomorphicCriteria(String attributeName, String operator, String value) {
        super(attributeName, operator, value);
    }

    public static HomomorphicCriteria getInstance(String operator, String attributeName) {
        // Extend this case to support more operators.
        switch (operator) {
        case "+":
        case "*":
            return new HomomorphicCriteria(attributeName, operator, null);
        default:
            throw new UnsupportedOperationException("The homomrphic operation '" + operator + "' is not supported");
        }
    }
}
