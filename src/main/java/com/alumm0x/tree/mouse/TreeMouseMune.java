package com.alumm0x.tree.mouse;

import com.alumm0x.listeners.HttpListener;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.ScanEngine;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.ui.AnalysisUI;
import com.alumm0x.ui.SettingUI;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Objects;

public class TreeMouseMune {

    public static ImageIcon nodeIcon = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("icon.jpg")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));

    public static JPopupMenu getMune(TreePath path) {

        JPopupMenu menu = new JPopupMenu ();
        // 路径标题，有长度限制，太长了就中间...
        DefaultMutableTreeNode note = (DefaultMutableTreeNode) path.getLastPathComponent();
        UselessTreeNodeEntity entity = (UselessTreeNodeEntity) note.getUserObject();
        String nodename = note.toString();
        if (nodename.length() > 50) {
            String pre = nodename.substring(0,30);
            String end = nodename.substring(nodename.length()-20);
            nodename = pre + "..." + end;
        }
        JMenuItem title = new JMenuItem (nodename);
        title.setIcon(nodeIcon); // 设置个图标
        // 添加host到范围白名单，根据白名单过滤数据渲染JTree
        JMenuItem add_scope = new JMenuItem ( "Add blacklist" );
        add_scope.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取第二层path，也就是domain那层，root下面的那层
                DefaultMutableTreeNode root2 = (DefaultMutableTreeNode)path.getPathComponent(1);
                SettingUI.notInsideAdd(CommonStore.TARGET_SCOPE, root2.toString()); //无重复再添加
                // JList更新数据必须通过setModel，重新设置数据
                SettingUI.scope_list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.TARGET_SCOPE.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.TARGET_SCOPE.get(i);
                    }
                });
                // 将添加黑名单的都设置为isVisible=false
                ((UselessTreeNodeEntity)root2.getUserObject()).setVisible(false); // 本身设置为false
                AnalysisUI.isVisibleAllNodes(new TreePath(root2), false); // 递归所有子节点为false
                CommonStore.TREE.updateUI();
            }
        });
        // 扫描动作-动态扫描
        JMenu scan = new JMenu("Scan");
        JMenu scan_search = new JMenu("Scan search");
        addMenuItem("IDOR", entity,scan);
        addMenuItemBySearch("IDOR", scan_search);
        addMenuItem("Redirect", entity,scan);
        addMenuItemBySearch("Redirect", scan_search);
        addMenuItem("Csrf", entity,scan);
        addMenuItemBySearch("Csrf", scan_search);
        addMenuItem("JsonCsrf", entity,scan);
        addMenuItemBySearch("JsonCsrf", scan_search);
        addMenuItem("BeanParamInject", entity,scan);
        addMenuItemBySearch("BeanParamInject", scan_search);
        addMenuItem("BypassAuth", entity,scan);
        addMenuItemBySearch("BypassAuth", scan_search);
        addMenuItem("WebSocketHijacking", entity,scan);
        addMenuItemBySearch("WebSocketHijacking", scan_search);
        addMenuItem("Ssrf", entity,scan);
        addMenuItemBySearch("Ssrf", scan_search);
        addMenuItem("Upload", entity,scan);
        addMenuItemBySearch("Upload", scan_search);
        addMenuItem("JWT", entity,scan);
        addMenuItemBySearch("JWT", scan_search);

        // 展开tree
        JMenu expand = new JMenu("Expand branch");
        JMenuItem expand_select = new JMenuItem ( "Expand select branch" );
        expand_select.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                    HttpListener.expandAllNodes(path, true);
            }
        });
        JMenuItem expand_all = new JMenuItem ( "Expand all branch" );
        expand_all.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HttpListener.expandAllNodes(new TreePath(CommonStore.ROOTNODE), true);
            }
        });
        expand.add(expand_select);
        expand.add(expand_all);

        // 折叠tree
        JMenu collapse = new JMenu("Collapse branch");
        JMenuItem collapse_select = new JMenuItem ( "Collapse select branch" );
        collapse_select.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HttpListener.expandAllNodes(path, false);
            }
        });
        JMenuItem collapse_all = new JMenuItem ( "Collapse all branch" );
        collapse_all.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HttpListener.expandAllNodes(new TreePath(CommonStore.ROOTNODE), false);
            }
        });
        collapse.add(collapse_select);
        collapse.add(collapse_all);
        // 删除当前节点
        JMenu delete = new JMenu("Delete branch");
        JMenuItem delete_select = new JMenuItem ( "Delete select branch" );
        delete_select.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                note.removeFromParent();
                CommonStore.TREE.updateUI();
            }
        });
        JMenuItem delete_all = new JMenuItem ( "Delete all branch" );
        delete_all.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //确认是否
                int opt = JOptionPane.showConfirmDialog(delete_all,
                        "请确认你要删除所有数据?", "确认信息",
                        JOptionPane.YES_NO_OPTION);
                if (opt == JOptionPane.YES_OPTION) {
                    //确认继续操作
                    CommonStore.ROOTNODE.removeAllChildren(); //删除所有节点
                    CommonStore.ALL_TAGS.clear(); //清空标签
                    CommonStore.TREE.updateUI();
                }
            }
        });
        delete.add(delete_select);
        delete.add(delete_all);
        // 网站分析的一些东西
        JMenu analysis = new JMenu("analysis");
        JMenuItem relation = new JMenuItem("relation"); // 1.分析这个网站业务的交互域名
        analysis.add(relation);

        // 布局各组件
        menu.setBorderPainted(true); //绘制边框
        menu.add(title);
        menu.addSeparator(); //分割符
        menu.add(add_scope);
        menu.addSeparator(); //分割符
        menu.add(scan);
        menu.add(scan_search);
        menu.addSeparator(); //分割符
        menu.add(expand);
        menu.add(collapse);
        menu.add (delete);
        menu.addSeparator(); //分割符
        menu.add(analysis);

        return  menu;
    }

    /**
     * 添加漏洞菜单,将选中的请求发送到任务列表
     */
    private static void addMenuItem(String name, UselessTreeNodeEntity entity,JMenu... menus) {
        for (JMenu m : menus) {
            JMenuItem poc = new JMenuItem(name);
            poc.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // 点击后添加扫描任务
                    String pocvalue = ((JMenuItem) e.getSource()).getText();
                    if (entity.getRequestResponse() != null) {
                        // 添加扫描任务的逻辑，因为需要根据验证结果修改entity的color跟pocs
                        ScanEngine.addScan(pocvalue, entity);
                    }
                }
            });
            m.add(poc);
        }
    }

    /**
     * 添加漏洞菜单,将搜索结果的所有请求发送到任务列表
     */
    private static void addMenuItemBySearch(String name,JMenu... menus) {
        for (JMenu m : menus) {
            JMenuItem poc = new JMenuItem(name);
            poc.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // 点击后添加扫描任务,会将当前搜索的结果加入扫描
                    String pocvalue = ((JMenuItem)e.getSource()).getText();
                    addScanFormSearch(new TreePath(CommonStore.ROOTNODE), pocvalue);
                }
            });
            m.add(poc);
        }
    }

    /**
     * 遍历搜索结果，以添加所有结果到扫描
     */
    private static void addScanFormSearch(TreePath parent, String poc){
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration e = node.children(); e.hasMoreElements();) {
                DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                UselessTreeNodeEntity entity = ((UselessTreeNodeEntity)n.getUserObject()); // 修改isVisible
                // 并限制不搜索第二层node，也就是domain那层，那层是没有数据的，纯粹为了归类请求
                if (entity.isVisible() && entity.getCurrent().startsWith("[")) {
                    // 只有有请求的才会被添加
                    if (entity.getRequestResponse() != null) {
                        // 添加扫描任务的逻辑,需要传入的数entity，因为需要根据验证结果修改entity的color跟pocs
                        ScanEngine.addScan(poc, entity);
                    }
                }
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                addScanFormSearch(path,poc); // 递归子节点，进行查询
            }
        }
    }
}
