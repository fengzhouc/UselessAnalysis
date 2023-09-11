package com.alumm0x.ui;

import javax.swing.*;

import com.alumm0x.util.CommonStore;

import java.awt.*;

public class UIShow {
    /**
     * 这里是组装各个部分的UI
     */
    public static Component getUI(){
        JPanel contentPane = new JPanel();
        contentPane.setLayout(new BorderLayout());
        JTabbedPane jTabbedPane = new JTabbedPane();
        jTabbedPane.addTab("Analysis", AnalysisUI.getUI());
        JTabbedPane scanner = new JTabbedPane();
        scanner.addTab("Scan Logger",ScanLoggerUI.getUI());
        scanner.addTab("Pocs Detail",PocsDetailUI.getUI());
        jTabbedPane.addTab("Scanner", scanner);
        jTabbedPane.addTab("Setting", SettingUI.getUI());
        contentPane.add(jTabbedPane);
        // 保存burpJFrame，用于自定义弹窗
        CommonStore.burpJFrame = (JFrame)SwingUtilities.getRoot(jTabbedPane);
        
        return contentPane;
    }
}
