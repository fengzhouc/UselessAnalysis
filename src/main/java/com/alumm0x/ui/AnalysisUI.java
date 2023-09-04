package com.alumm0x.ui;

import com.alumm0x.listeners.HttpListener;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.ToolsUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

public class AnalysisUI {

    public static JTextField add_tab; //添加的标签
    public static MultiComboBoxToViewTag tags; //搜索条件中的标签选择
    public static MultiComboBox methods; //搜索条件中的method选择
    public static MultiComboBox colors; //搜索条件中的method选择
    public static JComboBox<String> type; //搜索类型
    public static JTextField search; //搜索的值

    public static Component getUI(){
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(0, 5, 0, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
//        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));


        // 设置的UI
        JPanel tools = new JPanel();
        tools.setBorder(new EmptyBorder(0, 0, 0, 0)); //组件间间隙
        BoxLayout tools_boxLayout = new BoxLayout(tools, BoxLayout.Y_AXIS);
        tools.setLayout(tools_boxLayout);
        // 设置：过滤的UI
        JCheckBox on = new JCheckBox("On-Off (数据太多的话,会造成JVM内存不够,注意哈!!)");
        on.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                JCheckBox jcb = (JCheckBox) e.getItem();// 将得到的事件强制转化为JCheckBox类
                // 判断是否被选择
                CommonStore.ON_OFF = jcb.isSelected();
            }
        });
        // 搜索功能
        search = new JTextField(); //输入框，自定义后缀
        search.setColumns(20);
        search.setText("");
        JButton search_go = new JButton("Go");
        search_go.setToolTipText("支持基于上次的结果进行再搜索.");
        search_go.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                search(new TreePath(CommonStore.ROOTNODE));
                CommonStore.TREE.updateUI();
            }
        });
        JButton search_clear = new JButton("Clear");
        search_clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // clear就是把所有节点的isVisible设置为true，这样就会展示所有了
                isVisibleAllNodes(new TreePath(CommonStore.ROOTNODE),true);
                search.setText("");
                CommonStore.TREE.updateUI();
            }
        });
        // 搜索目标类型（任意值/参数）
        type = new JComboBox<>();
        type.addItem("");
        type.addItem("Url");
        type.addItem("Status");
        type.addItem("Domain");
        type.addItem("Params");
        type.addItem("ReqHeader");
        type.addItem("RespHeader");
        // tag的多选框
        tags = new MultiComboBoxToViewTag();
        // method的多选框
        String[] methodArr = new String[]{"GET","POST","DELETE","PUT","PATCH","OPTIONS","HEAD","TRACE"};
        methods = new MultiComboBox(Arrays.asList(methodArr));
        // color的多选框
        String[] colorArr = new String[]{"red","magenta","yellow","green"};
        colors = new MultiComboBox(Arrays.asList(colorArr));
        // 组装工具区
        SettingUI.makeJpanel(tools,on);
        SettingUI.makeJpanel(tools,new JLabel("Search:"),search,search_go,search_clear,new JLabel("#Scope:"), type,new JLabel("#Tags:"),tags,new JLabel("#Methods:"),methods,new JLabel("#Colors:"),colors);

        //上下分割界面
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
        splitPane.setDividerLocation(0.3); //设置分隔条的位置为 JSplitPane 大小的一个百分比,70%->0.7,貌似没啥用
        splitPane.setResizeWeight(0.3);
        // 1.上面板，Jtree
        HttpListener httpListener = (HttpListener) CommonStore.callbacks.getHttpListeners().stream().filter(ls -> ls instanceof HttpListener).findFirst().get();
        JScrollPane scrollPane = new JScrollPane(CommonStore.TREE); //滚动条
        scrollPane.setPreferredSize(new Dimension(1000, 500));
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);
        // 2.下面板，请求响应的面板
        JTabbedPane tabs = new JTabbedPane();
        CommonStore.requestViewer = CommonStore.callbacks.createMessageEditor(httpListener, false);
        CommonStore.responseViewer = CommonStore.callbacks.createMessageEditor(httpListener, false);
        tabs.addTab("Request", CommonStore.requestViewer.getComponent());
        tabs.addTab("Response", CommonStore.responseViewer.getComponent());
        splitPane.setRightComponent(tabs);

        //左右分割界面
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); //左右分割
        split.setDividerLocation(0.7); //设置分隔条的位置为 JSplitPane 大小的一个百分比,70%->0.7
        split.setResizeWeight(0.7);
        //右侧信息展示区的基础面板
        // 1.标签区
        CommonStore.list = new JList<>();
        CommonStore.list.setLayoutOrientation(JList.VERTICAL);
        CommonStore.list.setModel(new AbstractListModel<String>() {
            public int getSize() {
                return CommonStore.entity.tabs.size();
            }
            public String getElementAt(int i) {
                return CommonStore.entity.tabs.get(i);
            }
        });
        JScrollPane default_scrollPane = new JScrollPane(CommonStore.list);
        default_scrollPane.setPreferredSize(new Dimension(350, 100));
        default_scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 1.1 添加/删除/清空等的按钮
        JButton add = new JButton("Add");
        add.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = add_tab.getText();
                if (!"".equalsIgnoreCase(value)){
                    ToolsUtil.notInsideAdd(CommonStore.entity.tabs, value); //无重复再添加
                    // JList更新数据必须通过setModel，重新设置数据
                    CommonStore.list.setModel(new AbstractListModel<String>() {
                        public int getSize() {
                            return CommonStore.entity.tabs.size();
                        }
                        public String getElementAt(int i) {
                            return CommonStore.entity.tabs.get(i);
                        }
                    });
                }
            }
        });
        add_tab = new JTextField(); //输入框，自定义后缀
        add_tab.setColumns(10);
        JButton romove = new JButton("Remove");
        romove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectValue = CommonStore.list.getSelectedValue();
                CommonStore.entity.tabs.remove(selectValue);
                // JList更新数据必须通过setModel，重新设置数据
                CommonStore.list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.entity.tabs.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.entity.tabs.get(i);
                    }
                });
            }
        });
        JButton clear_tab = new JButton("Clear");
        clear_tab.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CommonStore.entity.tabs.clear();
                // JList更新数据必须通过setModel，重新设置数据
                CommonStore.list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.entity.tabs.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.entity.tabs.get(i);
                    }
                });
            }
        });
        //1.2 组装标签ui
        JPanel tabPanl = new JPanel();
        tabPanl.setBorder(new EmptyBorder(0, 0, 0, 0)); //组件间间隙
//        BoxLayout tabPanl_boxLayout = new BoxLayout(tabPanl, BoxLayout.Y_AXIS);
        VerticalFlowLayout tabPanl_boxLayout = new VerticalFlowLayout();; // 自定义的垂直布局
        tabPanl.setLayout(tabPanl_boxLayout);
        JLabel tab = new JLabel("标签区");
        SettingUI.makeJpanel(tabPanl, tab);
        SettingUI.makeJpanel(tabPanl, default_scrollPane);
        SettingUI.makeJpanel(tabPanl, add, add_tab, romove, clear_tab);
        JLabel mess_text = new JLabel("分析结果区");
        SettingUI.makeJpanel(tabPanl, mess_text);

        //2.组装信息展示区的ui
        JPanel message = new JPanel();
        message.setBorder(new EmptyBorder(0, 0, 0, 0)); //组件间间隙
        BoxLayout message_boxLayout = new BoxLayout(message, BoxLayout.Y_AXIS);
//        VerticalFlowLayout message_boxLayout = new VerticalFlowLayout();; // 自定义的垂直布局
        message.setLayout(message_boxLayout);
        // 计划折叠按钮，内涵表格展示数据(key/value/operate)
        CommonStore.foldTableComponent_query = new FoldTableComponent("Query Parameters", CommonStore.QUERY_TABLEMODEL);
        JPanel t1 = CommonStore.foldTableComponent_query.getUI();
        CommonStore.foldTableComponent_reqheader = new FoldTableComponent("Non-Standard ReqHeaders", CommonStore.REQHEADER_TABLEMODEL);
        JPanel t2 = CommonStore.foldTableComponent_reqheader.getUI();
        CommonStore.foldTableComponent_respheader = new FoldTableComponent("Non-Standard RespHeaders", CommonStore.RESPHEADER_TABLEMODEL);
        JPanel t3 = CommonStore.foldTableComponent_respheader.getUI();
        CommonStore.foldTableComponent_session = new FoldTableComponent("Session Credentials", CommonStore.SESSION_TABLEMODEL);
        JPanel t4 = CommonStore.foldTableComponent_session.getUI();
        CommonStore.foldTableComponent_sec = new FoldTableComponent("Possible Security Risks", CommonStore.SEC_TABLEMODEL);
        JPanel t5 = CommonStore.foldTableComponent_sec.getUI();
        CommonStore.foldTableComponent_poc = new FoldTableComponent("Poc Hunter", CommonStore.POC_TABLEMODEL);
        JPanel t6 = CommonStore.foldTableComponent_poc.getUI();
        SettingUI.makeJpanel(message, t1);
        SettingUI.makeJpanel(message, t2);
        SettingUI.makeJpanel(message, t3);
        SettingUI.makeJpanel(message, t4);
        SettingUI.makeJpanel(message, t5);
        SettingUI.makeJpanel(message, t6);


        //2.右侧总ui
        JPanel rightPanl = new JPanel();
        rightPanl.setBorder(new EmptyBorder(0, 0, 0, 0)); //组件间间隙
        VerticalFlowLayout rightPanl_boxLayout = new VerticalFlowLayout();; // 自定义的垂直布局
        rightPanl.setLayout(rightPanl_boxLayout);
        SettingUI.makeJpanel(rightPanl,  tabPanl);
        SettingUI.makeJpanel(rightPanl,  message);

        split.setLeftComponent(splitPane);
        split.setRightComponent(rightPanl);

        // 组装完整UI
        contentPane.add(tools, BorderLayout.NORTH);
        contentPane.add(split, BorderLayout.CENTER);

        return contentPane;
    }

    /**
     * 设置所有节点的isVisible
     * @param parent 根节点
     * @param isVisible 展开与否
     */
    public static void isVisibleAllNodes(TreePath parent, boolean isVisible) {
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
                DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                UselessTreeNodeEntity entity = (UselessTreeNodeEntity)n.getUserObject();
                // 仅检查domain那个节点，在黑名单，则不修改，只有不在黑名单中，才可以释放，这样保证黑名单最优先的逻辑
                if (!entity.getCurrent().startsWith("[")) {
                    isVisible = !SettingUI.isBlackList(entity);
                }
                entity.setVisible(isVisible);
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                isVisibleAllNodes(path, isVisible); // 递归子节点，设置展开
            }
        }
    }

    /**
     * 搜索功能，指定搜索的父节点，然后进行递归遍历搜索
     */
    public static void search(TreePath parent){
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
                DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                UselessTreeNodeEntity entity = ((UselessTreeNodeEntity)n.getUserObject()); // 修改isVisible
                // 为了可以继续上次的搜索结果在进行搜索，这里限制了仅搜索isVisible=true的节点
                if (entity.isVisible()) {
                    // 并限制不搜索第二层node，也就是domain那层，那层是没有数据的，纯粹为了归类请求
                    if (entity.getCurrent().startsWith("[")) {
                        // 如果有选择标签的话，进入标签匹配逻辑
                        if (tags.getSelectedValues().size() > 0) {
                            boolean hit = false;
                            for (String tag : entity.tabs) {
                                if (tags.getSelectedValues().contains(tag)) {
                                    hit = true;
                                    break;
                                }
                            }
                            entity.setVisible(hit);
                        }
                        // 如果有选择method的话，进入标签匹配逻辑
                        if (methods.getSelectedValues().size() > 0) {
                            boolean hit = false;
                            for (String method : methods.getSelectedValues()) {
                                if (entity.getCurrent().contains(method)) {
                                    hit = true;
                                    break;
                                }
                            }
                            entity.setVisible(hit);
                        }
                        // 如果有选择color的话，进入标签匹配逻辑
                        if (colors.getSelectedValues().size() > 0) {
                            boolean hit = colors.getSelectedValues().contains(entity.color);
                            entity.setVisible(hit);
                        }
                        // 进入特定字符的搜索 TODO 待完善各部分逻辑
                        if (!search.getText().equals("")) {
                            boolean hit = false;
                            switch ((String) Objects.requireNonNull(type.getSelectedItem())) {
                                case "Url":
                                    if (BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()).contains(search.getText())) {
                                        hit = true;
                                    }
                                    break;
                                case "Params":
                                    // 检查查询参数
                                    if (Objects.requireNonNull(BurpReqRespTools.getQuery(entity.getRequestResponse())).contains(search.getText())) {
                                        hit = true;
                                    }
                                    // 检查请求体参数
                                    if (new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).contains(search.getText())) {
                                        hit = true;
                                    }
                                    break;
                                case "ReqHeader":
                                    for (String iterable_element : Objects.requireNonNull(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()))) {
                                        if (iterable_element.contains(search.getText())) {
                                            hit = true;
                                            break;
                                        }
                                    }
                                    break;
                                case "RespHeader":
                                    for (String iterable_element : Objects.requireNonNull(BurpReqRespTools.getRespHeaders(entity.getRequestResponse()))) {
                                        if (iterable_element.contains(search.getText())) {
                                            hit = true;
                                            break;
                                        }
                                    }
                                    break;
                                case "Status":
                                    if (BurpReqRespTools.getStatus(entity.getRequestResponse()) == Short.parseShort(search.getText())) {
                                        hit = true;
                                    }
                                    break;
                                case "Domain":
                                    if (Objects.requireNonNull(BurpReqRespTools.getHttpService(entity.getRequestResponse())).getHost().contains(search.getText())) {
                                        hit = true;
                                    }
                                    break;
                            }
                            entity.setVisible(hit);
                        }
                    }
                }
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                search(path); // 递归子节点，进行查询
            }
        }
    }
}


