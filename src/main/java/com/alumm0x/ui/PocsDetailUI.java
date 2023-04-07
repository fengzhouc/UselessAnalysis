package com.alumm0x.ui;

import com.alumm0x.scan.PocsDetailTableModel;
import com.alumm0x.util.CommonStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;

public class PocsDetailUI {

    public static Component getUI() {
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(0, 5, 0, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        // 初始化表格
        CommonStore.pocsTable = new JTable(new PocsDetailTableModel());
        CommonStore.pocsTable.getTableHeader().setReorderingAllowed(false); //不允许拖动表头来挑战列
        CommonStore.pocsTable.getTableHeader().setBackground(Color.LIGHT_GRAY); //设置表头底色
        CommonStore.pocsTable.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, CommonStore.pocsTable.getTableHeader().getFont().getSize())); //设置表头字体加粗
        // 居中的样式
        DefaultTableCellRenderer render = new DefaultTableCellRenderer();
        render.setHorizontalAlignment(SwingConstants.CENTER);
        // 设置列宽
        TableColumnModel cm = CommonStore.pocsTable.getColumnModel();
        TableColumn id = cm.getColumn(0);
        id.setCellRenderer(render);
        id.setPreferredWidth(50);
        id.setMaxWidth(100);
        id.setMinWidth(50);
        TableColumn name = cm.getColumn(1);
        name.setCellRenderer(render);
        name.setPreferredWidth(200);
        name.setMaxWidth(300);
        name.setMinWidth(200);

        JScrollPane scrollPane = new JScrollPane(CommonStore.pocsTable); //滚动条
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);


        // 组装完整UI
        contentPane.add(scrollPane, BorderLayout.CENTER);
        return contentPane;
    }
}