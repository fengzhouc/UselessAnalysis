package com.alumm0x.ui;

import com.alumm0x.mouse.DataHandlerMouseMune;
import com.alumm0x.ui.tablemodel.RisksTable;
import com.alumm0x.util.CommonStore;

import burp.ITextEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class RisksUI {

    // public static IMessageEditor risksViewer; // 显示选中的risk的内容，用于复制
    public static ITextEditor risksViewer; // 显示选中的risk的内容，用于复制
    public static JTabbedPane riskViewPane; // 显示内容的Pane
    public static JSplitPane splitPane; // 用于选中行后才添加riskViewPane

    public static Component getUI() {
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(0, 5, 0, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        // 初始化表格
        JTable riskTable = new RisksTable(CommonStore.RISKS_TABLEMODEL);
        riskTable.getTableHeader().setReorderingAllowed(false); //不允许拖动表头来挑战列
        riskTable.getTableHeader().setBackground(Color.LIGHT_GRAY); //设置表头底色
        riskTable.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD,riskTable.getTableHeader().getFont().getSize())); //设置表头字体加粗
        // 居中的样式
        DefaultTableCellRenderer render = new DefaultTableCellRenderer();
        render.setHorizontalAlignment(SwingConstants.CENTER);
        // 设置列宽
        TableColumnModel cm = riskTable.getColumnModel();
        TableColumn id = cm.getColumn(0);
        id.setCellRenderer(render);
        id.setPreferredWidth(200);
        id.setMaxWidth(300);
        id.setMinWidth(200);
        TableColumn name = cm.getColumn(1);
        name.setCellRenderer(render);
        name.setPreferredWidth(200);
        name.setMaxWidth(300);
        name.setMinWidth(200);

        JScrollPane scrollPane = new JScrollPane(riskTable); //滚动条
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        //上下分割界面
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
        splitPane.setDividerLocation(0.3); //设置分隔条的位置为 JSplitPane 大小的一个百分比,70%->0.7,貌似没啥用
        splitPane.setResizeWeight(0.3); 

        // 下面板，risk的内容展示面板
        riskViewPane = new JTabbedPane();
        // risksViewer = CommonStore.callbacks.createMessageEditor((HttpListener) CommonStore.callbacks.getHttpListeners().stream().filter(ls -> ls instanceof HttpListener).findFirst().get(), false);
        risksViewer = CommonStore.callbacks.createTextEditor();
        // 右键菜单
        risksViewer.getComponent().addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    // 限制右击
                    if (SwingUtilities.isRightMouseButton(e)) {
                        Rectangle pathBounds = risksViewer.getComponent().getBounds(); // 获取组件边界
                        if ( pathBounds != null && pathBounds.contains (e.getX(), e.getY())) {
                            JPopupMenu menu = DataHandlerMouseMune.getMune(risksViewer.getSelectedText());
                            menu.show (risksViewer.getComponent(), e.getX(), e.getY());
                        }
                    }
                }
            });
        riskViewPane.addTab("Risk", risksViewer.getComponent());

        // 组装
        splitPane.setLeftComponent(scrollPane);


        // 组装完整UI
        contentPane.add(splitPane, BorderLayout.CENTER);
        return contentPane;
    }

}