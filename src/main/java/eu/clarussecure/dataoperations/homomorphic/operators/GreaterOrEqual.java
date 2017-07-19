package eu.clarussecure.dataoperations.homomorphic.operators;

public class GreaterOrEqual extends Select {

    public GreaterOrEqual(String threshold) {
        this.threshold = threshold;
    }

    @Override
    public boolean select(String data) {
        double numericData = Double.parseDouble(data);
        double numericThreshold = Double.parseDouble(this.threshold);

        return numericData >= numericThreshold;
    }

}
