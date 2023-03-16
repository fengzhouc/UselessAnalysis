package com.alumm0x.scan;

import com.alumm0x.util.CommonStore;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

public class ScanLoggerTableModel extends AbstractTableModel {


    public ScanLoggerTableModel() {}

    /**
     * 获取行数
     * @return
     */
    @Override
    public int getRowCount() {
        return CommonStore.log.size();
    }

    /**
     * 获取字段数
     * @return
     */
    @Override
    public int getColumnCount() {
        return 6;
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
                return "id"; // 任务ID
            case 1:
                return "url"; // 验证的url
            case 2:
                return "status"; // 响应状态码
            case 3:
                return "poc"; // 任务状态
            case 4:
                return "scanning"; // 任务状态
            case 5:
                return "comments"; // 简单的描述
            default:
                return "";
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
        LogEntry logEntry = CommonStore.log.get(CommonStore.logTable.convertRowIndexToModel(rowIndex));
        if (logEntry != null) {
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.Url;
                case 2:
                    return logEntry.Status;
                case 3:
                    return logEntry.Poc;
                case 4:
                    return logEntry.getScanning();
                case 5:
                    return logEntry.Comments;
                default:
                    return "";
            }
        }else {
            return "";
        }
    }

    /**
     * 更新表格
     */
    public void update(){
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                fireTableDataChanged();
            }
        });
    }
}


