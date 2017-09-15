package eu.clarussecure.dataoperations.homomorphic;

import eu.clarussecure.dataoperations.DataOperationResponse;
import java.util.Random;

public class HomomorphicResult extends DataOperationResponse {

    public HomomorphicResult(String[] attributeNames, String[][] content) {
        super.id = new Random().nextInt();
        super.attributeNames = attributeNames;
        super.contents = content;
    }

    public String[][] getDecryptedContent() {
        return this.contents;
    }

    public String[] getDecryptedAttributeNames() {
        return this.attributeNames;
    }
}
