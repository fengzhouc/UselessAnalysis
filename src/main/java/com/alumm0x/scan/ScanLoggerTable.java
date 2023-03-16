package com.alumm0x.scan;

import com.alumm0x.util.CommonStore;

import javax.swing.*;
import javax.swing.table.TableModel;


public class ScanLoggerTable extends JTable {
    public ScanLoggerTable(TableModel tableModel)
    {
        super(tableModel);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        LogEntry logEntry = CommonStore.log.get(this.convertRowIndexToModel(row));
        if (logEntry.requestResponse != null) {
            CommonStore.scan_requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            CommonStore.scan_responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            CommonStore.currentlyDisplayedItem = logEntry.requestResponse;
        }
        super.changeSelection(row, col, toggle, extend);
    }
}
