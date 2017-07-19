package eu.clarussecure.dataoperations.homomorphic.testing;

import eu.clarussecure.dataoperations.Criteria;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

public class Cloud {
    // Dommy implementation for a cloud
    // The implementation is a table, saving columns and rows.

    private List<String[]> data;
    private final String[] columns; // attributes

    public Cloud(String[] columns) {
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
        //String[][] results = new String[data.size()][protectedAttribNames.length];

        // TODO - Process the criteria to filter the data
        // IDEA - This could be done in this part of the code.
        for (String[] row : data) { // Select each row of the loaded data
            int p = 0; // column position in the results table
            String[] selectedRow = new String[protectedAttribNames.length]; // new result row
            for (int i = 0; i < columns.length; i++) { // for each stored column name
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
            results.add(selectedRow);
        }
        return results.toArray(new String[results.size()][]);
    }

    public String printCloudContents() {
        String ret = Arrays.deepToString(columns) + "\n";

        for (String[] row : data) {
            ret += Arrays.deepToString(row) + "\n";
        }
        return ret;
    }
}
