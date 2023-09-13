package com.alumm0x.mouse;

import com.alumm0x.ui.RisksUI;
import com.alumm0x.ui.UIShow;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;

import burp.ITextEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;

/**
 * 用于处理数据的，比如加解密
 */
public class DataHandlerMouseMune {

    public static ImageIcon nodeIcon = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("icon.jpg")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));

    /**
     * 右键菜单
     * @param selectdata 待处理的数据
     * @return
     */
    public static JPopupMenu getMune(byte[] selectdata) {

        JPopupMenu menu = new JPopupMenu ();

        JMenuItem title = new JMenuItem ("DataHanders");
        title.setIcon(nodeIcon); // 设置个图标
        // 编解码、加解密相关
        JMenu crypto = new JMenu("Crypto"); // 加解密相关
        // url编码
        JMenu url = new JMenu("Url");
        addMenuItem("Url-encode", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createDialog("Url-encode", CommonStore.helpers.urlEncode(selectdata));
            }
        }, url);
        addMenuItem("Url-decode", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createDialog("Url-decode", CommonStore.helpers.urlDecode(selectdata));
            }
            
        }, url);
        // base64编码
        JMenu base64 = new JMenu("Basee64");
        addMenuItem("Basee64-encode", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createDialog("Basee64-encode", CommonStore.helpers.base64Encode(selectdata).getBytes(StandardCharsets.UTF_8));
            }
        }, base64);
        addMenuItem("Basee64-decode", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createDialog("Basee64-decode", CommonStore.helpers.base64Decode(selectdata));
            }
        }, base64);
        // hash计算
        JMenu hash = new JMenu("Hash");
        // TODO: 聪明的解码，那就是根据具体的编码进行解码
        JMenuItem smart_decode = new JMenuItem("Smart-decode");
        crypto.add(url);
        crypto.add(base64);
        crypto.add(hash);
        crypto.add(smart_decode);
        // 数据特殊处理,比如将选中数据转为javascript，
        JMenu convert = new JMenu("Convert");
        convert.add(new JMenuItem("Convert for Javascript"));
        // 生成攻击payload
        JMenu generate = new JMenu("Generate");
        generate.add(new JMenuItem("Generate for Fatjson_CVE"));
        // 数据分析，分析填入的数据
        JMenu analysis = new JMenu("Analysis");
        analysis.add(new JMenuItem("Analysis for Serialize Data"));
    
        // 布局各组件
        menu.setBorderPainted(true); //绘制边框
        menu.add(title);
        menu.addSeparator(); //分割符
        menu.add(crypto);
        menu.addSeparator(); //分割符
        menu.add(convert);
        menu.add(generate);
        menu.addSeparator(); //分割符
        menu.add(analysis);

        return  menu;
    }

    /**
     * 添加漏洞菜单,将选中的请求发送到任务列表
     */
    private static void addMenuItem(String name, ActionListener actionListener,JMenu... menus) {
        for (JMenu m : menus) {
            JMenuItem poc = new JMenuItem(name);
            poc.addActionListener(actionListener);
            m.add(poc);
        }
    }

    /**
     * 创建弹窗组件
     * @param title 窗口标题
     * @param data 窗口显示的数据
     */
    private static void createDialog(String title, byte[] data){
        //创建JDialog
        JDialog dialog=new JDialog(CommonStore.burpJFrame, title, true); 
        dialog.setSize(400, 250);
        dialog.setResizable(false);
        // 设置弹窗局中
        // setLocationRelativeTo 设定一个窗口的相对于另外一个窗口的位置（一般是居中于父窗口的中间），如果owner==null则窗口就居于屏幕的中央
        dialog.setLocationRelativeTo(UIShow.contentPane);
        // 构造内容显示的pane
        JPanel panel=new JPanel();
        panel.setLayout(new FlowLayout());
        panel.setBorder(new EmptyBorder(0, 0, 0, 0));
        panel.setLayout(new FlowLayout(FlowLayout.LEFT));
        // 使用TEXT组件显示内容
        ITextEditor content = CommonStore.callbacks.createTextEditor();
        content.setEditable(false);
        content.getComponent().setPreferredSize(new Dimension(300, 200));
        content.setText(data);
        // 将内容pane添加到弹窗组件
        panel.add(content.getComponent());
        dialog.setContentPane(panel);

        //显示对话框（setVisible()方法会阻塞，直到对话框关闭）
        dialog.setVisible(true);
    }
}
