package com.alumm0x.ui.tablemodel;

import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.util.HashMap;
import java.util.Map;

public class MyTableModel extends AbstractTableModel {

    protected Map<String, Object> messages  = new HashMap<>(); //默认空数据

    public  MyTableModel() {}

    public void setMessages(Map<String, Object> datas) {
        this.messages = datas;
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                fireTableDataChanged();
            }
        });
    }

    /**
     * 获取行数
     * @return
     */
    @Override
    public int getRowCount() {
        return this.messages.size();
    }

    /**
     * 获取字段数
     * @return
     */
    @Override
    public int getColumnCount() {
        return 3;
    }

    /**
     * 获取字段名
     * @param columnIndex 字段序号
     * @return 返回字段名
     */
    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex) {
            case 0:
                return "NAME";
            case 1:
                return "VALUE";
            default:
                return ""; //这里返回按钮
        }
    }

    /**
     * 根据行列获取对应的字段值
     * @param rowIndex 行号
     * @param columnIndex 列号
     * @return 返回对应值
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        int index = 0;
        for (String key : this.messages.keySet()) {
            if (index == rowIndex) {
                switch (columnIndex) {
                    case 0:
                        return key;
                    case 1:
                        return this.messages.get(key);
                    default:
                        return ""; //这里返回按钮，点击进入当前行的详细展示UI
                }
            }
            ++index;
        }
        return "";
    }
}
