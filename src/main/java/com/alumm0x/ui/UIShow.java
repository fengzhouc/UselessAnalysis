package com.alumm0x.ui;

import javax.swing.*;
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
        return contentPane;
    }
}
