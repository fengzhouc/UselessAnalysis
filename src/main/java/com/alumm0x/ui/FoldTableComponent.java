package com.alumm0x.ui;

import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;

import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;

/**
 * 封装一个按钮折叠table的组件，因为会创建多个，封装好复用
 */
public class FoldTableComponent {

    protected JButton button; //按钮
    protected JPanel foldPanl; //折叠的内容都放在这个组件
    protected JTable table; //表格
    protected JScrollPane tscrollPane; //表格滚动条
    protected boolean expand = false; //是否展开，默认不展开
    protected JPanel root; //总的组件
    protected String name;
    ImageIcon right = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("right.png")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));
    ImageIcon down = new ImageIcon(new ImageIcon(SourceLoader.loadSourceToUrl("down.png")).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH));

    private JTabbedPane infoViewPane;
    private IMessageEditor infoViewer; // 展示选中行的完整信息
    private JSplitPane splitPane;

    public FoldTableComponent(String name, TableModel tableModel) {
        this.name = name;
        // 初始化总ui
        this.root = new JPanel();
        this.root.setBorder(new EmptyBorder(0, 0, 0, 0));
        this.root.setLayout(new BoxLayout(this.root, BoxLayout.Y_AXIS));
        // 创建按钮，根据传入的name，也就是分类
        this.button = new JButton(name);
        this.button.setBorderPainted(false); //去掉按钮边框
        this.button.setIcon(right); // 默认向右图标，跟随默认折叠状态
        this.button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                expand();
                if (expand) {
                    // 展开某个的时候，把其他已展开的折叠上
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            collapseOther(name);
                        }
                    });
                }
            }
        });
        // 初始化表格
        this.table = new FoldTableComponentTable(tableModel);
        this.table.setPreferredSize(new Dimension(330, this.table.getTableHeader().getHeight() + this.table.getRowHeight()));
        this.table.getTableHeader().setReorderingAllowed(false); //不允许拖动表头来挑战列
        this.table.getTableHeader().setBackground(Color.LIGHT_GRAY); //设置表头底色
        this.table.getTableHeader().setFont(new Font(Font.SANS_SERIF,  Font.BOLD, this.table.getTableHeader().getFont().getSize())); //设置表头字体加粗
        // 左对齐的样式
        DefaultTableCellRenderer render = new DefaultTableCellRenderer();
        render.setHorizontalAlignment(SwingConstants.LEFT);
        // 设置列数据左对齐
        TableColumnModel cm = this.table.getColumnModel();
        TableColumn tname = cm.getColumn(0);
        tname.setCellRenderer(render);
        tname.setPreferredWidth(100);

        TableColumn tvalue = cm.getColumn(1);
        tvalue.setCellRenderer(render);
        tvalue.setPreferredWidth(220);


        // 组装折叠的表格组件
        this.foldPanl = new JPanel();
        this.foldPanl.setBorder(new EmptyBorder(0, 0, 0, 0));
        this.foldPanl.setLayout(new FlowLayout(FlowLayout.LEFT));
        this.foldPanl.setVisible(expand); //默认不展开
        tscrollPane = new JScrollPane(this.table); //滚动条
        // tscrollPane.setPreferredSize(new Dimension(335, this.table.getTableHeader().getHeight() + this.table.getRowHeight()));
        // tscrollPane.setPreferredSize(new Dimension(335, 100));
        tscrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED); // 垂直方向滚动

        //上下分割界面
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //上下分割
        // splitPane.setEnabled(false); // 禁止滚动
        splitPane.setDividerLocation(0.3); //设置分隔条的位置为 JSplitPane 大小的一个百分比,70%->0.7,貌似没啥用
        splitPane.setResizeWeight(0.3);
        splitPane.setPreferredSize(new Dimension(335, 300)); // 限制整个splitPane的大小，这样在添加一侧组件的时候会填满，再添加另一侧后即可按0.3进行分割

        // 下面板，risk的内容展示面板
        infoViewPane = new JTabbedPane();
        // infoViewPane.setPreferredSize(new Dimension(335, 200));
        infoViewer = CommonStore.callbacks.createMessageEditor(null, false);
        infoViewPane.add("Detail", infoViewer.getComponent());

        // 组装
        splitPane.setLeftComponent(tscrollPane);
        // splitPane.setRightComponent(infoViewPane); 

        SettingUI.makeJpanel(this.foldPanl, splitPane);
        // 组装总ui
        SettingUI.makeJpanel(this.root, this.button);
        SettingUI.makeJpanel(this.root, this.foldPanl);
    }

    public JPanel getUI() {
        return this.root;
    }

    /**
     * 重新设置按钮的名称,未来可能会把表格数据显示在按钮上，这样更直观
     * 还有就是根据表格行数调整滚动条的高度
     */
    public void updateButtonName() {
        // this.table.setPreferredSize(new Dimension(335, this.table.getTableHeader().getHeight() + this.table.getRowHeight() * this.table.getRowCount()));
        // if (0 < this.table.getRowCount() && this.table.getRowCount() < 5){
        //     tscrollPane.setPreferredSize(new Dimension(335, this.table.getTableHeader().getHeight() + this.table.getRowHeight()  * (this.table.getRowCount() + 1)));
        // }else if (this.table.getRowCount() >= 5){
        //     tscrollPane.setPreferredSize(new Dimension(335, this.table.getTableHeader().getHeight() + this.table.getRowHeight()  * 5));
        // }
        this.button.setText(this.button.getText().split(" \\(")[0] + " (" + this.table.getRowCount() + ")");
        // 清空数据，为什么在这里执行，因为tree切换选中节点的时候都会调用这个方法
        infoViewer.setMessage("".getBytes(StandardCharsets.UTF_8), false); // 清空信息
        // 折叠后就删除tab
        if (splitPane.getRightComponent() != null) {
            splitPane.remove(infoViewPane);
        }
    }

    /**
     * 折叠表格
     */
    public void expand() {
        this.expand = !this.expand;
        foldPanl.setVisible(this.expand);
        if (expand) {
            button.setIcon(down);
        } else {
            button.setIcon(right);
        }
    }
    /**
     * 关掉其他展开的表格，只允许展开一个
     * @param name 折叠的标题
     */
    public void collapseOther(String name) {
        if (!name.equals(CommonStore.foldTableComponent_query.name) && CommonStore.foldTableComponent_query.expand) {
            CommonStore.foldTableComponent_query.expand();
            CommonStore.foldTableComponent_query.foldPanl.updateUI();
        }
        if (!name.equals(CommonStore.foldTableComponent_session.name) && CommonStore.foldTableComponent_session.expand) {
            CommonStore.foldTableComponent_session.expand();
            CommonStore.foldTableComponent_session.foldPanl.updateUI();
        }
        if (!name.equals(CommonStore.foldTableComponent_respheader.name) && CommonStore.foldTableComponent_respheader.expand) {
            CommonStore.foldTableComponent_respheader.expand();
            CommonStore.foldTableComponent_respheader.foldPanl.updateUI();
        }
        if (!name.equals(CommonStore.foldTableComponent_reqheader.name) && CommonStore.foldTableComponent_reqheader.expand) {
            CommonStore.foldTableComponent_reqheader.expand();
            CommonStore.foldTableComponent_reqheader.foldPanl.updateUI();
        }
    }

    /**
     * 拓展JTable，选中即展示详细完整内容
     */
    private class FoldTableComponentTable extends JTable {

        public FoldTableComponentTable(TableModel tableModel)
            {
                super(tableModel);
            }

            @Override
            public void changeSelection(int row, int col, boolean toggle, boolean extend)
            {
                StringBuffer stringBuffer = new StringBuffer();
                stringBuffer.append("Name: ").append(this.getValueAt(row, 0)).append("\r\n");
                stringBuffer.append("Value: ").append(this.getValueAt(row, 1)).append("\r\n");
                infoViewer.setMessage(stringBuffer.toString().getBytes(StandardCharsets.UTF_8), false);
                // 选中后才显示具体内容
                // infoViewPane.add("Detail", infoViewer.getComponent());
                splitPane.setRightComponent(infoViewPane); 
                // UI的更新需要新线程
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        // infoViewPane.updateUI();
                        splitPane.updateUI();
                    }
                });

                super.changeSelection(row, col, toggle, extend);
            }
    }
}
