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
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.basic.BasicArrowButton;


/**
 * 下拉复选框组件
 *
 */
public class MultiComboBox extends JComponent implements ActionListener {

    private MultiPopup popup;
    private JTextField editor;
    protected JButton arrowButton;
    private final List<String> values;

    public MultiComboBox(List<String> values) {
        this.values = values;
        initComponent();
    }

    private void initComponent() {
        this.setLayout(new BorderLayout());
        popup = new MultiPopup(this.values);
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
            popup.show(this, 0, getHeight());
            popup.refreshCheckboxPane();
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
        private final List<String> values;

        public MultiPopup(List<String> values) {
            super();
            this.values = values;
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
            JCheckBox allselect = new JCheckBox("全选");
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
            for (JCheckBox box : checkBoxList) {
                checkboxPane.add(box);
            }
        }

        /**
         * 动态更新checkboxPane，因为tag实时变化的
         */
        public void refreshCheckboxPane() {
            for (String v : this.values) {
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
                    // 根据复选框梳理更新样式，保持尺寸符合内容
                    checkboxPane.setLayout(new GridLayout(checkBoxList.size(), 1, 3, 3));
                }
                this.updateUI();
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
