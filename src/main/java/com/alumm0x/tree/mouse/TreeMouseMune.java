package com.alumm0x.tree.mouse;

import com.alumm0x.listeners.HttpListener;
import com.alumm0x.scan.ScanEngine;
import com.alumm0x.scan.StaticScanEngine;
import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.ui.AnalysisUI;
import com.alumm0x.ui.SettingUI;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TreeMouseMune {

    public static ImageIcon nodeIcon = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("icon.jpg")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));

    public static JPopupMenu getMune(TreePath path) {

        JPopupMenu menu = new JPopupMenu ();
        // 路径标题，有长度限制，太长了就中间...
        DefaultMutableTreeNode note = (DefaultMutableTreeNode) path.getLastPathComponent();
        // 当前选中节点的entity
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
                ToolsUtil.notInsideAdd(CommonStore.TARGET_SCOPE, root2.toString()); //无重复再添加
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
        JMenu scan_static = new JMenu("StaticCheck");
        scan.add(scan_static);
        JMenu scan_search = new JMenu("Scan search");
        JMenu scan_search_static = new JMenu("StaticCheck");
        scan_search.add(scan_search_static);
        // 添加TaskImpl子类的菜单，也就是主动扫描任务
        for (Class<? extends TaskImpl> task : ScanEngine.tasks) {
            try{
                addMenuItem(task.getSimpleName(), new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 点击后添加扫描任务
                        String pocvalue = ((JMenuItem) e.getSource()).getText();
                        if (entity.getRequestResponse() != null) {
                            // 添加扫描任务的逻辑，因为需要根据验证结果修改entity的color跟pocs
                            ScanEngine.addScan(pocvalue, entity);
                        }
                    }
                },scan);
                addMenuItemBySearch(task.getSimpleName(), new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 点击后添加扫描任务,会将当前搜索的结果加入扫描
                        String pocvalue = ((JMenuItem)e.getSource()).getText();
                        addScanFormSearch(new TreePath(CommonStore.ROOTNODE), pocvalue);
                    }
                }, scan_search);
            } catch (SecurityException | IllegalArgumentException e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }
        // 添加执行所有静态检查的菜单
        addMenuItem("ALL", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 点击后添加扫描任务
                String pocvalue = ((JMenuItem) e.getSource()).getText();
                if (entity.getRequestResponse() != null) {
                    // 添加扫描任务的逻辑，因为需要根据验证结果修改entity的color跟pocs
                    StaticScanEngine.addScan(pocvalue, entity);
                }
            }
        },scan_static);
        addMenuItemBySearch("ALL", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 点击后添加扫描任务,会将当前搜索的结果加入扫描
                String pocvalue = ((JMenuItem)e.getSource()).getText();
                addStaticScanFormSearch(new TreePath(CommonStore.ROOTNODE), pocvalue);
            }
        }, scan_search_static);
        // 添加StaticTaskImpl子类的菜单，也就是静态检查的触发菜单
        for (Class<? extends StaticTaskImpl> task : StaticScanEngine.tasks) {
            try{
                addMenuItem(task.getSimpleName(), new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 点击后添加扫描任务
                        String pocvalue = ((JMenuItem) e.getSource()).getText();
                        if (entity.getRequestResponse() != null) {
                            // 添加扫描任务的逻辑，因为需要根据验证结果修改entity的color跟pocs
                            StaticScanEngine.addScan(pocvalue, entity);
                        }
                    }
                },scan_static);
                addMenuItemBySearch(task.getSimpleName(), new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 点击后添加扫描任务,会将当前搜索的结果加入扫描
                        String pocvalue = ((JMenuItem)e.getSource()).getText();
                        addStaticScanFormSearch(new TreePath(CommonStore.ROOTNODE), pocvalue);
                    }
                }, scan_search_static);
            } catch (SecurityException | IllegalArgumentException e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }

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
                    // CommonStore.VIEW_TAGS.clear(); //清空标签
                    AnalysisUI.tags.removeCheckBoxList(); //清空标签多选框控件
                    CommonStore.TREE.updateUI();
                }
            }
        });
        delete.add(delete_select);
        delete.add(delete_all);
        // 网站分析的一些东西
        JMenu analysis = new JMenu("Analysis");
        JMenuItem relation = new JMenuItem("Relation"); // 1.分析这个网站业务的交互域名
        relation.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                java.util.List<Object> relations = new ArrayList<>();
                // 分析交互
                analysisForRelationByHost(path, entity, relations);
                // 弹窗显示
                JOptionPane.showMessageDialog(relation, creatTreeString(relations, 0));
            }
            
        });
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
    private static void addMenuItem(String name, ActionListener actionListener,JMenu... menus) {
        for (JMenu m : menus) {
            JMenuItem poc = new JMenuItem(name);
            poc.addActionListener(actionListener);
            m.add(poc);
        }
    }

    /**
     * 添加漏洞菜单,将搜索结果的所有请求发送到任务列表
     */
    private static void addMenuItemBySearch(String name, ActionListener actionListener,JMenu... menus) {
        for (JMenu m : menus) {
            JMenuItem poc = new JMenuItem(name);
            poc.addActionListener(actionListener);
            m.add(poc);
        }
    }

    /**
     * 遍历搜索结果，以添加所有结果到扫描
     */
    private static void addScanFormSearch(TreePath parent, String poc){
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
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

    /**
     * 遍历搜索结果，以添加所有结果到静态扫描
     */
    private static void addStaticScanFormSearch(TreePath parent, String poc){
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
                DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                UselessTreeNodeEntity entity = ((UselessTreeNodeEntity)n.getUserObject()); // 修改isVisible
                // 并限制不搜索第二层node，也就是domain那层，那层是没有数据的，纯粹为了归类请求
                if (entity.isVisible() && entity.getCurrent().startsWith("[")) {
                    // 只有有请求的才会被添加
                    if (entity.getRequestResponse() != null) {
                        // 添加扫描任务的逻辑,需要传入的数entity，因为需要根据验证结果修改entity的color跟pocs
                        StaticScanEngine.addScan(poc, entity);
                    }
                }
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                addStaticScanFormSearch(path,poc); // 递归子节点，进行查询
            }
        }
    }

    /**
     * 分析所选节点及其子节点的所有交互host
     * @param parant 当前所选节点，也即是getMune(TreePath path)的入参
     * @param entity 当前节点的存储的UselessTreeNodeEntity对象
     * @param relations 存储所有交互站点的list
     */
    private static void analysisForRelationByHost(TreePath parent, UselessTreeNodeEntity entity, java.util.List<Object> relations){
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        // 正则获取域名
        String regex = "http[s]?://(.*?)[/&\"]+?\\w*?"; //分组获取域名
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(entity.getCurrent());
        String host = null; // 获取的主机
        if (matcher.find()){//没匹配到则不进行后续验证
            host = matcher.group(1);
        }
        // 看是否有子节点，有则遍历
        if (node.getChildCount() > 0) {
            // 存在子节点则不需要考虑是否有添加过，有子节点的就必须添加
            relations.add(Objects.requireNonNull(host)); // 添加host
            // 遍历子节点
            java.util.List<Object> childs = new ArrayList<>();
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
                DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                UselessTreeNodeEntity entity1 = ((UselessTreeNodeEntity)n.getUserObject());
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                analysisForRelationByHost(path, entity1, childs); // 递归子节点，进行查询
            }
            // 子节点遍历完了就添加进去
            relations.add(childs);
        } else {
            // 没有子节点的就不重复添加
            ToolsUtil.notInsideAdd(relations, Objects.requireNonNull(host));
        }
    }

    /**
     * 将list按层级构造出树的文本
     * @param list 数据集合
     * @param deep 当前的层级
     * @return 返回树结构的文本
     */
    private static String creatTreeString(java.util.List<Object> list, int deep) {
        StringBuffer stringBuffer = new StringBuffer();
        for (Object object : list) {
            // 先尝试转换list
            java.util.List<Object> l = ToolsUtil.castList(object, Object.class);
            if (l != null) {
                stringBuffer.append(creatTreeString(l, deep + 1));
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append("|");
                for (int i = 0; i < deep; i++) {
                    sb.append("--");
                }
                stringBuffer.append(sb.toString() + "| @" + (String)object + "\n");
            }
        }
        return stringBuffer.toString();
    }
}
