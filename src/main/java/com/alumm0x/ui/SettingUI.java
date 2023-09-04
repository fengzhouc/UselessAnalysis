package com.alumm0x.ui;

import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.ToolsUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SettingUI {

    public static JTextField add_suffix; //添加的特征值
    public static JTextField add_scope; //添加的target
    public static JTextField add_redirect; //添加的redirect
    public static JList<String> scope_list;//scope的列表
    public static JList<String> redirect_list;//重定向字段的列表
    public static JComboBox<String> comboBox; //referrer策略的下拉框

    public static Component getUI(){
        JPanel contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 0, 0, 0)); //组件间间隙
        contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));

        //1.构造总设置UI
        JPanel options = new JPanel();
        options.setBorder(new EmptyBorder(0, 5, 0, 5)); //组件间间隙
        BoxLayout options_boxLayout = new BoxLayout(options, BoxLayout.Y_AXIS);
        options.setLayout(options_boxLayout);
        // 2.自定义后缀的操作
        JList<String> list = new JList<>();
        list.setLayoutOrientation(JList.VERTICAL);
        list.setModel(new AbstractListModel<String>() {
            public int getSize() {
                return CommonStore.CUSTOMIZE_SUFFIX.size();
            }
            public String getElementAt(int i) {
                return CommonStore.CUSTOMIZE_SUFFIX.get(i);
            }
        });
        JScrollPane default_scrollPane = new JScrollPane(list);
        default_scrollPane.setPreferredSize(new Dimension(350, 100));
        default_scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 3.1 添加/删除/清空等的按钮
        JButton add = new JButton("Add");
        add.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = SettingUI.add_suffix.getText();
                if (!"".equalsIgnoreCase(value)) {
                    ToolsUtil.notInsideAdd(CommonStore.CUSTOMIZE_SUFFIX, value); //无重复再添加
                    // JList更新数据必须通过setModel，重新设置数据
                    list.setModel(new AbstractListModel<String>() {
                        public int getSize() {
                            return CommonStore.CUSTOMIZE_SUFFIX.size();
                        }
                        public String getElementAt(int i) {
                            return CommonStore.CUSTOMIZE_SUFFIX.get(i);
                        }
                    });
                    SettingUI.add_suffix.setText("");
                }
            }
        });
        add_suffix = new JTextField(); //输入框，自定义后缀
        add_suffix.setColumns(10);
        add_suffix.setText("");
        JButton romove = new JButton("Remove");
        romove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectValue = list.getSelectedValue();
                CommonStore.CUSTOMIZE_SUFFIX.remove(selectValue);
                // JList更新数据必须通过setModel，重新设置数据
                list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.CUSTOMIZE_SUFFIX.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.CUSTOMIZE_SUFFIX.get(i);
                    }
                });
            }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CommonStore.CUSTOMIZE_SUFFIX.clear();
                // JList更新数据必须通过setModel，重新设置数据
                list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.CUSTOMIZE_SUFFIX.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.CUSTOMIZE_SUFFIX.get(i);
                    }
                });
            }
        });

        //3.2 组装按钮,并添加到options
        JLabel ct = new JLabel("黑名单: Content-Type/Suffix (用于限制采集的请求范围)");

        makeJpanel(options, ct);
        makeJpanel(options, default_scrollPane);
        makeJpanel(options, add, add_suffix, romove, clear);

        // 4.创建下拉框
        comboBox = new JComboBox<>();
        // 绑定下拉框选项
        String[] strArray = {"默认目标de设置" ,"unsafe-url", "strict-origin-when-cross-origin", "no-referrer-when-downgrade", "strict-origin", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "no-referrer"};
        for (String item : strArray)
        {
            comboBox.addItem(item);
        }
        makeJpanel(options, new JLabel("Referrer策略 (推荐值按下拉顺序)"));
        makeJpanel(options, comboBox);

        // target scope的设置
        scope_list = new JList<>();
        scope_list.setLayoutOrientation(JList.VERTICAL);
        scope_list.setModel(new AbstractListModel<String>() {
            public int getSize() {
                return CommonStore.TARGET_SCOPE.size();
            }
            public String getElementAt(int i) {
                return CommonStore.TARGET_SCOPE.get(i);
            }
        });
        JScrollPane scope_default_scrollPane = new JScrollPane(scope_list);
        scope_default_scrollPane.setPreferredSize(new Dimension(350, 100));
        scope_default_scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 3.1 添加/删除/清空等的按钮
        JButton scope_add = new JButton("Add");
        scope_add.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = SettingUI.add_scope.getText();
                if (!"".equalsIgnoreCase(value)) {
                    ToolsUtil.notInsideAdd(CommonStore.TARGET_SCOPE, value); //无重复再添加
                    // JList更新数据必须通过setModel，重新设置数据
                    scope_list.setModel(new AbstractListModel<String>() {
                        public int getSize() {
                            return CommonStore.TARGET_SCOPE.size();
                        }
                        public String getElementAt(int i) {
                            return CommonStore.TARGET_SCOPE.get(i);
                        }
                    });
                    // 添加单个黑名单，需要将这个节点下的所有的设为false
                    AnalysisUI.isVisibleAllNodes(new TreePath(CommonStore.ROOTNODE), false);
                    CommonStore.TREE.updateUI();
                    SettingUI.add_scope.setText("");
                }
            }
        });
        add_scope = new JTextField(); //输入框，自定义后缀
        add_scope.setColumns(10);
        add_scope.setText("");
        JButton scope_romove = new JButton("Remove");
        scope_romove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectValue = scope_list.getSelectedValue();
                CommonStore.TARGET_SCOPE.remove(selectValue);
                // JList更新数据必须通过setModel，重新设置数据
                scope_list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.TARGET_SCOPE.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.TARGET_SCOPE.get(i);
                    }
                });
                // 移除单个黑名单，需要将这个节点下的所有的设为true
                AnalysisUI.isVisibleAllNodes(new TreePath(CommonStore.ROOTNODE), true);
                CommonStore.TREE.updateUI();
            }
        });
        JButton scope_clear = new JButton("Clear");
        scope_clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CommonStore.TARGET_SCOPE.clear();
                // JList更新数据必须通过setModel，重新设置数据
                scope_list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.TARGET_SCOPE.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.TARGET_SCOPE.get(i);
                    }
                });
                // 清空黑名单的话，就把所有数据展示
                AnalysisUI.isVisibleAllNodes(new TreePath(CommonStore.ROOTNODE), true);
                CommonStore.TREE.updateUI();
            }
        });
        JLabel cp = new JLabel("树视图黑名单 (控制树的展示,支持域名的模糊匹配,eg:'*.example.com')");
        makeJpanel(options, cp);
        makeJpanel(options, scope_default_scrollPane);
        makeJpanel(options, scope_add, add_scope, scope_romove, scope_clear);

        // 右侧的配置UI
        JPanel rightPanel = new JPanel();
        rightPanel.setBorder(new EmptyBorder(0, 5, 0, 5)); //组件间间隙
        BoxLayout rightPanel_boxLayout = new BoxLayout(rightPanel, BoxLayout.Y_AXIS);
        rightPanel.setLayout(rightPanel_boxLayout);
        // 重定向的设置
        redirect_list = new JList<>();
        redirect_list.setLayoutOrientation(JList.VERTICAL);
        redirect_list.setModel(new AbstractListModel<String>() {
            public int getSize() {
                return CommonStore.REDIRECT_SCOPE.size();
            }
            public String getElementAt(int i) {
                return CommonStore.REDIRECT_SCOPE.get(i);
            }
        });
        JScrollPane redirect_default_scrollPane = new JScrollPane(redirect_list);
        redirect_default_scrollPane.setPreferredSize(new Dimension(350, 100));
        redirect_default_scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 3.1 添加/删除/清空等的按钮
        JButton redirect_add = new JButton("Add");
        redirect_add.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String value = SettingUI.add_redirect.getText();
                if (!"".equalsIgnoreCase(value)) {
                    ToolsUtil.notInsideAdd(CommonStore.REDIRECT_SCOPE, value); //无重复再添加
                    // JList更新数据必须通过setModel，重新设置数据
                    redirect_list.setModel(new AbstractListModel<String>() {
                        public int getSize() {
                            return CommonStore.REDIRECT_SCOPE.size();
                        }
                        public String getElementAt(int i) {
                            return CommonStore.REDIRECT_SCOPE.get(i);
                        }
                    });
                    SettingUI.add_redirect.setText("");
                }
            }
        });
        add_redirect = new JTextField(); //输入框，自定义后缀
        add_redirect.setColumns(10);
        add_redirect.setText("");
        JButton redirect_romove = new JButton("Remove");
        redirect_romove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectValue = redirect_list.getSelectedValue();
                CommonStore.REDIRECT_SCOPE.remove(selectValue);
                // JList更新数据必须通过setModel，重新设置数据
                redirect_list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.REDIRECT_SCOPE.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.REDIRECT_SCOPE.get(i);
                    }
                });
            }
        });
        JButton redirect_clear = new JButton("Clear");
        redirect_clear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CommonStore.REDIRECT_SCOPE.clear();
                // JList更新数据必须通过setModel，重新设置数据
                redirect_list.setModel(new AbstractListModel<String>() {
                    public int getSize() {
                        return CommonStore.REDIRECT_SCOPE.size();
                    }
                    public String getElementAt(int i) {
                        return CommonStore.REDIRECT_SCOPE.get(i);
                    }
                });
            }
        });
        JLabel redirect = new JLabel("Redirect检测的字段名称");
        makeJpanel(options, redirect);
        makeJpanel(options, redirect_default_scrollPane);
        makeJpanel(options, redirect_add, add_redirect, redirect_romove, redirect_clear);

        //4.组装总UI
        makeJpanel(contentPane, options);

        return contentPane;
    }

    /**
     * 添加多个组件组合到一个面板，再组合指定面板中
     * @param all 目标面板
     * @param components 待组装的组件
     */
    public static void makeJpanel(JPanel all, Component... components)
    {
        JPanel jPanel = new JPanel();
        jPanel.setBorder(new EmptyBorder(0, 0, 0, 0)); //组件间间隙
        FlowLayout flowLayout = (FlowLayout) jPanel.getLayout();
        flowLayout.setAlignment(FlowLayout.LEFT);
        for (Component component : components) {
            jPanel.add(component);
        }
        all.add(jPanel);
    }

    /**
     * 检查节点对象是否在被名单中
     * @param entity 节点保存的UserObject
     * @return boolean
     */
    public static boolean isBlackList(UselessTreeNodeEntity entity) {
        // 设置某path下所有节点的isVisible需要优先判断是否在黑名单，在则不修改
        for (String scope : CommonStore.TARGET_SCOPE) {
            // 如果在黑名单中，则把isVisible改为false，后续递归的多有子节点同步，这样保证黑名单优先逻辑
            if (entity.getCurrent().equals(scope) || entity.getCurrent().contains(scope.replace("*", ""))) {
                return true;
            }
        }
        return false;
    }
}
