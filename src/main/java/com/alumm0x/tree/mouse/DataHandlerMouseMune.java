package com.alumm0x.tree.mouse;

import com.alumm0x.util.SourceLoader;

import javax.swing.*;
import java.awt.*;

/**
 * 用于处理数据的，比如加解密
 */
public class DataHandlerMouseMune {

    public static ImageIcon nodeIcon = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("icon.jpg")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));

    public static JPopupMenu getMune() {

        JPopupMenu menu = new JPopupMenu ();

        JMenuItem title = new JMenuItem ("DataHanders");
        title.setIcon(nodeIcon); // 设置个图标
        // 扫描动作-动态扫描
        JMenu encode = new JMenu("encode");
        JMenu encode_base64 = new JMenu("Basee64");
        encode.add(encode_base64);
        JMenu decode = new JMenu("decode");
        JMenu decode_base64 = new JMenu("Basee64");
        decode.add(decode_base64);

    

        // 布局各组件
        menu.setBorderPainted(true); //绘制边框
        menu.add(title);
        menu.addSeparator(); //分割符
        menu.add(encode);
        menu.add(decode);

        return  menu;
    }
}
