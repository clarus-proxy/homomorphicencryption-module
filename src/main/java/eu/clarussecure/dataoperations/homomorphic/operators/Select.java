package eu.clarussecure.dataoperations.homomorphic.operators;

public abstract class Select {
    // This is the Interface for the data Selectors
    // It implements a factory based on the given operator argument (as string)

    // This is the funciton that will decide whether a data is selected or not
    // It MUST be implemented by all the sub classes.
    protected String threshold;

    public abstract boolean select(String data);

    public static Select getInstance(String operator, String threshold) {
        // Extend this list to implement more operators
        switch (operator) {
        case "id":
            return new Identity();
        case "=":
            return new Equals(threshold);
        case ">=":
            return new GreaterOrEqual(threshold);
        default:
            throw new UnsupportedOperationException("The operator '" + operator + "' is not supported.");
        }
    }
}
