package com.alumm0x.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import javax.swing.*;
import javax.swing.plaf.basic.BasicArrowButton;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;


/**
 * 下拉复选框组件
 *
 */
public class MultiComboBoxToViewTag extends JComponent implements ActionListener {

    private MultiPopup popup;
    private JTextField editor;
    protected JButton arrowButton;

    public MultiComboBoxToViewTag() {
        initComponent();
    }

    private void initComponent() {
        this.setLayout(new BorderLayout());
        popup = new MultiPopup();
        editor = new JTextField();
        editor.setBackground(Color.WHITE);
        editor.setEditable(false);
        editor.setPreferredSize(new Dimension(100, 20));
        editor.addActionListener(this);
        arrowButton = createArrowButton();
        arrowButton.addActionListener(this);
        add(editor, BorderLayout.WEST);
        add(arrowButton, BorderLayout.CENTER);
    }

    //获取选中的数据
    public List<String> getSelectedValues() {
        return popup.getSelectedValues();
    }

    //设置需要选中的值
    public void setSelectValues(Object[] selectvalues) {
        popup.setSelectValues(selectvalues);
        setText(selectvalues);
    }

    private void setText(Object[] values) {
        if (values.length > 0) {
            String value = Arrays.toString(values);
            value = value.replace("[", "");
            value = value.replace("]", "");
            editor.setText(value);
        }else {
            editor.setText("");
        }
    }

    /**
     * 删除所有复选框
     */
    public void removeCheckBoxList() {
        for (JCheckBox c : popup.checkBoxList) {
            if (!c.getText().equals("全选")) {
                popup.checkboxPane.remove(c);
            }
        }
        popup.checkBoxList.clear();
    }

    @Override
    public void actionPerformed(ActionEvent arg0) {
        // TODO Auto-generated method stub
        if (!popup.isVisible()) {
            popup.refreshCheckboxPane();
            popup.show(this, 0, getHeight());
        }
    }

    protected JButton createArrowButton() {
        JButton button = new BasicArrowButton(BasicArrowButton.SOUTH, UIManager.getColor("ComboBox.buttonBackground"),
                UIManager.getColor("ComboBox.buttonShadow"), UIManager.getColor("ComboBox.buttonDarkShadow"),
                UIManager.getColor("ComboBox.buttonHighlight"));
        button.setName("ComboBox.arrowButton");
        return button;
    }


    //内部类MultiPopup
    public class MultiPopup extends JPopupMenu implements ActionListener {
        private final List<JCheckBox> checkBoxList = new ArrayList<>();
        private JButton commitButton;
        private JButton cancelButton;
        public JPanel checkboxPane; // 标签复选框的面板
        private JCheckBox allselect;

        public MultiPopup() {
            super();
            initComponent();
        }

        private void initComponent() {
            initCheckboxPane();
            JPanel buttonPane = new JPanel();
            commitButton = new JButton("确定");
            commitButton.addActionListener(this);

            cancelButton = new JButton("取消");
            cancelButton.addActionListener(this);

            buttonPane.add(commitButton);
            buttonPane.add(cancelButton);

            JScrollPane checkboxtscrollPane = new JScrollPane(checkboxPane); //滚动条
            checkboxtscrollPane.setMaximumSize(new Dimension(checkboxPane.getWidth(),200)); // 设置最大size，这样超过这个大小就会出现滚动条
            checkboxtscrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED); // 垂直方向滚动

            this.add(checkboxtscrollPane, BorderLayout.CENTER);
            this.add(buttonPane, BorderLayout.SOUTH);
        }

        public void initCheckboxPane(){
            checkboxPane = new JPanel();
            checkboxPane.setLayout(new GridLayout(checkBoxList.size(), 1, 3, 3));
            this.setLayout(new BorderLayout());
            allselect = new JCheckBox("全选");
            allselect.addItemListener(new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (checkBoxList.get(0).isSelected()) {
                        for (JCheckBox checkBox : checkBoxList) {
                            if (!checkBox.isSelected()) {
                                checkBox.setSelected(true);
                            }
                        }
                    } else {
                        for (JCheckBox checkBox : checkBoxList) {
                            if (checkBox.isSelected()) {
                                checkBox.setSelected(false);
                            }
                        }
                    }
                }
            });
            checkBoxList.add(allselect);
            checkboxPane.add(allselect);
        }

        /**
         * 动态更新checkboxPane，因为tag实时变化的
         */
        public void refreshCheckboxPane() {
            // 先清空原来的checkBoxList
            checkBoxList.clear();
            checkboxPane.removeAll();
            checkBoxList.add(allselect); // 添加全选按钮
            checkboxPane.add(allselect); // 添加全选按钮
            // 清空CommonStore.VIEW_TAGS;
            CommonStore.VIEW_TAGS.clear();
            // 遍历tree树，将显示的node的标签
            initViewTags(new TreePath(CommonStore.ROOTNODE));
            // 检查显示的标签是否为0
            if (CommonStore.VIEW_TAGS.size() == 0) {
                // 为0则设置pane大小为初始化状态
                checkboxPane.setLayout(new GridLayout(checkBoxList.size(), 1, 3, 3));
                this.updateUI(); //更新UI
            } else {
                // 重新根据CommonStore.VIEW_TAGS构建checkBoxList
                for (String v : CommonStore.VIEW_TAGS) {
                    // 已有的复选框中没有的才添加
                    boolean in = false;
                    for (JCheckBox cb : checkBoxList) {
                        if (cb.getText().equals(v)) {
                            in = true;
                            break;
                        }
                    }
                    if (!in) {
                        JCheckBox temp = new JCheckBox(v);
                        checkBoxList.add(temp);
                        checkboxPane.add(temp);
                        // 根据复选框梳理更新样式，保持尺寸符合内容,最大行数15，超过则增加列数
                        if (checkBoxList.size() > 15){
                            checkboxPane.setLayout(new GridLayout(Math.round(checkBoxList.size() / Math.round(checkBoxList.size() / 15) + 1) + 1, Math.round(checkBoxList.size() / 15) + 1, 3, 3));
                        } else {
                            checkboxPane.setLayout(new GridLayout(checkBoxList.size(), 1, 3, 3));
                        }
                    }
                    this.updateUI();
                }
            }
        }

        // 初始化CommonStore.VIEW_TAGS，通过便利tree，将显示的节点的tag添加进去
        private void initViewTags(TreePath parent){
            TreeNode node = (TreeNode) parent.getLastPathComponent();
            if (node.getChildCount() > 0) {
                for (Enumeration e = node.children(); e.hasMoreElements();) {
                    DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.nextElement(); // 获取父节点的子节点
                    UselessTreeNodeEntity entity = ((UselessTreeNodeEntity)n.getUserObject()); // 修改isVisible
                    // 为了可以继续上次的搜索结果在进行搜索，这里限制了仅搜索isVisible=true的节点
                    if (entity.isVisible()) {
                        // 将显示的节点的标签添加到CommonStore.VIEW_TAGS，这样实现动态变化的标签列表
                        for (String tag : entity.tabs) {
                            SettingUI.notInsideAdd(CommonStore.VIEW_TAGS,tag);
                        } 
                    }
                    TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                    initViewTags(path); // 递归子节点，进行查询
                }
            }
        }

        public void setSelectValues(Object[] values) {
            if (values.length > 0) {
                for (Object value : values) {
                    for (JCheckBox jCheckBox : checkBoxList) {
                        if (value.equals(jCheckBox.getText())) {
                            jCheckBox.setSelected(true);
                        }
                    }
                }
                setText(getSelectedValues().toArray());
            }
        }

        public List<String> getSelectedValues() {
            List<String> selectedValues = new ArrayList<>();
            if (checkBoxList.get(0).getText().equals("全选")) {
                if (checkBoxList.get(0).isSelected()) {
                    for (JCheckBox checkBox : checkBoxList) {
                        selectedValues.add(checkBox.getText());
                    }
                } else {
                    for (JCheckBox checkBox : checkBoxList) {
                        if (checkBox.isSelected()) {
                            selectedValues.add(checkBox.getText());
                        }
                    }
                }
            } else {
                for (JCheckBox checkBox : checkBoxList) {
                    if (checkBox.isSelected()) {
                        selectedValues.add(checkBox.getText());
                    }
                }
            }

            return selectedValues;
        }



        @Override
        public void actionPerformed(ActionEvent arg0) {
            // TODO Auto-generated method stub
            Object source = arg0.getSource();
            if (source instanceof JButton) {
                JButton button = (JButton) source;
                if (button.equals(commitButton)) {
                    setText(getSelectedValues().toArray());
                    popup.setVisible(false);
                } else if (button.equals(cancelButton)) {
                    popup.setVisible(false);
                }
            }
        }

    }

}
