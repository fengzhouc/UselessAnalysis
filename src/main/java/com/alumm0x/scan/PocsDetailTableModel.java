package com.alumm0x.scan;

import com.alumm0x.util.CommonStore;

import javax.swing.table.AbstractTableModel;

public class PocsDetailTableModel extends AbstractTableModel {


    public PocsDetailTableModel() {}


    /**
     * 获取行数
     * @return
     */
    @Override
    public int getRowCount() {
        return CommonStore.pocs.size();
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
                return "id";
            case 1:
                return "name";
            case 2:
                return "comments";
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
        PocEntry poc = CommonStore.pocs.get(CommonStore.pocsTable.convertRowIndexToModel(rowIndex));
        if (poc != null) {
            switch (columnIndex) {
                case 0:
                    return poc.id;
                case 1:
                    return poc.Name;
                case 2:
                    return poc.Comments;
                default:
                    return "";
            }
        }else {
            return "";
        }
    }
}
