package eu.clarussecure.dataoperations.homomorphic.operators;

public class Identity extends Select {

    @Override
    public boolean select(String data) {
        // The identity function selects any given data
        // Since this is the identity function, it always returns true
        return true;
    }

}
