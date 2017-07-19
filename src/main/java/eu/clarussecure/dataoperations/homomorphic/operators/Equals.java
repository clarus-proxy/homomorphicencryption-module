package eu.clarussecure.dataoperations.homomorphic.operators;

public class Equals extends Select {
    public Equals(String threshold) {
        this.threshold = threshold;
    }

    @Override
    public boolean select(String data) {
        // This class has been . implemented for numeric values
        // First, parse the arguments
        double numericData = Double.parseDouble(data);
        double numericThreshold = Double.parseDouble(this.threshold);

        // Compare the data and return the result of the comparison
        return numericData == numericThreshold;
    }
}