package com.alumm0x.ui;

import com.alumm0x.listeners.HttpListener;
import com.alumm0x.scan.MytableCellRenderer;
import com.alumm0x.scan.ScanLoggerTable;
import com.alumm0x.scan.ScanLoggerTableModel;
import com.alumm0x.util.CommonStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;

public class ScanLoggerUI {

    public static Component getUI() {
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(0, 5, 0, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        //上下分割界面
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
        splitPane.setDividerLocation(0.3); //设置分隔条的位置为 JSplitPane 大小的一个百分比,70%->0.7,貌似没啥用
        splitPane.setResizeWeight(0.3);
        // 1.上面板，JTable
        // 初始化表格
        CommonStore.logModel = new ScanLoggerTableModel();
        CommonStore.logTable = new ScanLoggerTable(CommonStore.logModel);
        CommonStore.logTable.getTableHeader().setReorderingAllowed(false); //不允许拖动表头来挑战列
        CommonStore.logTable.getTableHeader().setBackground(Color.LIGHT_GRAY); //设置表头底色
        CommonStore.logTable.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, CommonStore.logTable.getTableHeader().getFont().getSize())); //设置表头字体加粗
        // 自定义的表格渲染，会根据color显示不同的底色，居中的样式
        MytableCellRenderer render = new MytableCellRenderer();
        render.setHorizontalAlignment(SwingConstants.CENTER);
        // 设置列宽
        TableColumnModel cm = CommonStore.logTable.getColumnModel();
        TableColumn id = cm.getColumn(0);
        id.setCellRenderer(render);
        id.setPreferredWidth(50);
        id.setMaxWidth(100);
        id.setMinWidth(50);
        TableColumn url = cm.getColumn(1);
        url.setPreferredWidth(500);
        url.setMaxWidth(1000);
        url.setMinWidth(500);
        TableColumn status = cm.getColumn(2);
        status.setCellRenderer(render);
        status.setPreferredWidth(100);
        status.setMaxWidth(200);
        status.setMinWidth(100);

        TableColumn poc = cm.getColumn(3);
        poc.setCellRenderer(render);
        poc.setPreferredWidth(200);
        poc.setMaxWidth(300);
        poc.setMinWidth(200);
        TableColumn scanning = cm.getColumn(4);
        scanning.setCellRenderer(render);
        scanning.setPreferredWidth(100);
        scanning.setMaxWidth(200);
        scanning.setMinWidth(100);

        JScrollPane scrollPane = new JScrollPane(CommonStore.logTable); //滚动条
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);
        // 2.下面板，请求响应的面板
        JTabbedPane tabs = new JTabbedPane();
        HttpListener httpListener = (HttpListener) CommonStore.callbacks.getHttpListeners().stream().filter(ls -> ls instanceof HttpListener).findFirst().get();
        CommonStore.scan_requestViewer = CommonStore.callbacks.createMessageEditor(httpListener, false);
        CommonStore.scan_responseViewer = CommonStore.callbacks.createMessageEditor(httpListener, false);
        tabs.addTab("Request", CommonStore.scan_requestViewer.getComponent());
        tabs.addTab("Response", CommonStore.scan_responseViewer.getComponent());
        splitPane.setRightComponent(tabs);

        // 组装完整UI
        contentPane.add(splitPane, BorderLayout.CENTER);
        return contentPane;
    }
}