package eu.clarussecure.dataoperations.homomorphic.testing;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.homomorphic.HomomorphicRemoteOperationCommand;
import eu.clarussecure.dataoperations.homomorphic.operators.Select;
import eu.clarussecure.encryption.paillier.EncryptedInteger;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class HomomorphicCloud {
    // Dommy implementation for a cloud
    // The implementation is a table, saving columns and rows.

    private final List<String[]> data;
    private final String[] columns; // attributes

    public HomomorphicCloud(String[] columns) {
        this.columns = columns;
        this.data = new ArrayList<>();
    }

    public void addRow(String[] row) {
        // It is assumed that the given arrays contains the columns in order!
        this.data.add(row);
    }

    public void addRows(String[][] rows) {
        // Each array will be added to the data
        this.data.addAll(Arrays.asList(rows));
    }

    public String[][] getRows(String[] protectedAttribNames, Criteria[] criteria) {
        // Select the columns regarding the required attribute names
        List<String[]> results = new ArrayList<>();

        // First, parse the selection criteria and prepare the Select instances
        Map<String, List<Select>> selectorsSet = new HashMap<>();

        // Initialize the selection criteria
        if (criteria == null) {
            // There is no criteria, use the Identity Function
            List<Select> selectors = selectorsSet.get("all");
            if (selectors == null) {
                selectors = new ArrayList<>();
                selectorsSet.put("all", selectors);
            }
            selectors.add(Select.getInstance("id", "")); // No threshold is required for the identity
        } else {
            // There are criteria. Build the selectors
            for (Criteria crit : criteria) {
                // Get the selectors of the attribute
                List<Select> selectors = selectorsSet.get(crit.getAttributeName());
                // Create the list of it does not exist
                if (selectors == null) {
                    selectors = new ArrayList<>();
                    selectorsSet.put(crit.getAttributeName(), selectors);
                }
                // Add the current selector to the list
                selectors.add(Select.getInstance(crit.getOperator(), crit.getValue()));
            }
        }

        // Second, process each column that will be selected
        for (String[] row : data) { // Select each row of the loaded data
            int p = 0; // column position in the results table
            String[] selectedRow = new String[protectedAttribNames.length]; // new result row
            boolean selected = true; // to decide if the row should be included in teh result or not

            for (int i = 0; i < columns.length; i++) { // for each stored column name
                // Get the selectors of this attribute
                List<Select> attributeSelectors = selectorsSet.get(columns[i]);
                // if no selectors were found, simply insert the identity
                if (attributeSelectors == null)
                    attributeSelectors = new ArrayList<>();
                // Do not forget the filters applied to "all";
                if (selectorsSet.get("all") != null) {
                    attributeSelectors.addAll(selectorsSet.get("all"));
                }

                // Evaluate each attribute selector
                for (Select selector : attributeSelectors) {
                    // Decide if the row should be selected or not
                    // NOTE - This line gives the "and" semantics to multiple criteria
                    selected = selected && selector.select(row[i]);
                }
                // Determine if this column is requested or not
                for (String protectedAttribName : protectedAttribNames) { //for each requested column
                    if (columns[i].equals(protectedAttribName)) { // check if this is a requested column
                        // Copy the value on position i (data stored in the requested column) in the found row
                        // to the row i, column p on the results
                        selectedRow[p] = row[i];
                        p++; // move to the left on the results table
                        break;
                    }
                }
            }
            // Include the row only if the selector says so
            if (selected) {
                results.add(selectedRow);
            }
        }
        return results.toArray(new String[results.size()][]);
    }

    public String[][] performHomomorphicComputation(String[] protectedAttribNames, Criteria[] criteria,
            HomomorphicRemoteOperationCommand command) {
        // Select the columns regarding the required attribute names
        List<String[]> involvedRows;
        String[] result;
        int i;

        // First, retrieve the involved rows.
        involvedRows = new ArrayList<>(Arrays.asList(this.getRows(protectedAttribNames, criteria)));

        // Second, perform the homomorphic operation
        // Find the index of the involved column
        for (i = 0; i < protectedAttribNames.length; i++) {
            if (protectedAttribNames[i].equals(command.getInvolvedColumn())) {
                break;
            }
        }
        final int index = i;
        // Reduce the involved rows into a single one.
        // NOTE: The other columns will retain a single value of the set
        // (one row, but it cannot be assured which, since Java can parallelize the reduce)
        // Create an auxiliary array with a zero encoded in the 
        String[] auxStart = involvedRows.get(0).clone();
        BigInteger auxZero = command.getEncryptedZero().getValue();
        auxStart[index] = Base64.getEncoder().encodeToString(auxZero.toByteArray());
        result = involvedRows.stream().reduce(auxStart.clone(), // Initial result creator
                (String[] row1, String[] row2) -> { // Reducing function: it takes two String arrays (rows) and reduce them homomorphically
                    try {
                        // Create the BigInteger object
                        // The values stored in the cloud are B64-encoded
                        BigInteger bigIntValueRow1 = new BigInteger(Base64.getDecoder().decode(row1[index]));
                        BigInteger bigIntValueRow2 = new BigInteger(Base64.getDecoder().decode(row2[index]));

                        // Create the EncryptedInteger objects to operate the values;
                        EncryptedInteger int1 = new EncryptedInteger(bigIntValueRow1, command.getPublicKey());
                        EncryptedInteger int2 = new EncryptedInteger(bigIntValueRow2, command.getPublicKey());

                        // Operate both values according to the given operation
                        BigInteger homoResult = null;
                        switch (command.getOperation()) {
                        case "+":
                            homoResult = int1.sum(int2).getValue();
                            break;
                        default:
                            throw new UnsupportedOperationException(
                                    "Homomorphic operation not supported: " + command.getOperation());
                        }
                        String[] res = row1.clone();
                        // Recover the bytes of the result BigInteger and B64-encode them
                        res[index] = Base64.getEncoder().encodeToString(homoResult.toByteArray());
                        return res;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                });
        return new String[][] { result };
    }

    public String decodeAndPrintCloudContents() {
        // This method is used to show the encoded versions of the clouds.
        String ret = Arrays.deepToString(columns) + "\n";

        for (String[] row : data) {
            String[] newRow = row.clone();
            for (int i = 0; i < row.length; i++) {
                if (this.columns[i].endsWith("_homoenc")) {
                    BigInteger integer = new BigInteger(Base64.getDecoder().decode(row[i]));
                    newRow[i] = integer.longValue() + "";
                } else {
                    newRow[i] = row[i];
                }
            }
            ret += Arrays.deepToString(newRow) + "\n";
        }
        return ret;
    }

    public String simplePrintCloudContents() {
        // This method is used to show the non-encoded versions of the clouds.
        String ret = Arrays.deepToString(columns) + "\n";

        for (String[] row : data) {
            ret += Arrays.deepToString(row) + "\n";
        }
        return ret;
    }
}
