package com.alumm0x.scan;

import javax.swing.*;

import javax.swing.table.DefaultTableCellRenderer;

import java.awt.*;


public class MytableCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

        //根据这里的值设置底色（verifying/默认色，has vuln!!!/red，Reuqest failed./yellow，Done/默认色）
        if (column == 4) {
            if (value.equals("has vuln!!!")) {
                setBackground(new Color(200, 0, 100));
            } else if (value.equals("Reuqest failed.")) {
                setBackground(new Color(200, 200, 0));
            } else {
                setBackground(null);
            }
        }else {
            setBackground(null);
        }
        return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
    }

}
