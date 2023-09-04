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
            stringBuffer.append("Desc: ").append(this.getValueAt(row, 0)).append("\r\n");
            stringBuffer.append("HitInfo: ").append(this.getValueAt(row, 1)).append("\r\n");
            stringBuffer.append("FixSuggestion: ").append(this.getValueAt(row, 2)).append("\r\n");
            RisksUI.risksViewer.setMessage(stringBuffer.toString().getBytes(StandardCharsets.UTF_8), false);
            // 选中才展示
            RisksUI.riskViewPane.addTab("Risk", RisksUI.risksViewer.getComponent());
            // UI的更新需要新线程
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        RisksUI.riskViewPane.updateUI();
                    }
                });

            super.changeSelection(row, col, toggle, extend);
        }
}
