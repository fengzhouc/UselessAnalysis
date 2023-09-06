package com.alumm0x.ui.tablemodel;


import java.nio.charset.StandardCharsets;

import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableModel;

import com.alumm0x.ui.RisksUI;


public class RisksTable extends JTable {

    public RisksTable(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("[Desc] \r\n").append(this.getValueAt(row, 0)).append("\r\n");
            stringBuffer.append("\r\n[HitInfo] \r\n").append(this.getValueAt(row, 1)).append("\r\n");
            stringBuffer.append("\r\n[FixSuggestion] \r\n").append(this.getValueAt(row, 2)).append("\r\n");
            // RisksUI.risksViewer.setMessage(CommonStore.helpers.stringToBytes(stringBuffer.toString()), false);
            RisksUI.risksViewer.setEditable(false);
            RisksUI.risksViewer.setText(stringBuffer.toString().getBytes(StandardCharsets.UTF_8));
            // 选中才展示
            RisksUI.splitPane.setRightComponent(RisksUI.riskViewPane);
            // UI的更新需要新线程
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    RisksUI.splitPane.updateUI();
                }
            });

            super.changeSelection(row, col, toggle, extend);
        }
}
