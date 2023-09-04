package com.alumm0x.tree;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Insets;
import java.awt.Rectangle;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.UIResource;
import javax.swing.plaf.basic.BasicGraphicsUtils;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeCellRenderer;

import com.alumm0x.ui.RisksUI;

import sun.swing.DefaultLookup;

public class MyTreeCellRenderer extends JLabel implements TreeCellRenderer {
    /** Last tree the renderer was painted in. */
    private JTree tree;

    /** Is the value currently selected. */
    protected boolean selected;
    /** True if has focus. */
    protected boolean hasFocus;
    /** True if draws focus border around icon as well. */
    private boolean drawsFocusBorderAroundIcon;
    /** If true, a dashed line is drawn as the focus indicator. */
    private boolean drawDashedFocusIndicator;

    // If drawDashedFocusIndicator is true, the following are used.
    /**
     * Background color of the tree.
     */
    private Color treeBGColor;
    /**
     * Color to draw the focus indicator in, determined from the background.
     * color.
     */
    private Color focusBGColor;

    // Icons
    /** Icon used to show non-leaf nodes that aren't expanded. */
    transient protected Icon closedIcon;

    /** Icon used to show leaf nodes. */
    transient protected Icon leafIcon;

    /** Icon used to show non-leaf nodes that are expanded. */
    transient protected Icon openIcon;

    // Colors
    /** Color to use for the foreground for selected nodes. */
    protected Color textSelectionColor;

    /** Color to use for the foreground for non-selected nodes. */
    protected Color textNonSelectionColor;

    /** Color to use for the background when a node is selected. */
    protected Color backgroundSelectionColor;

    /** Color to use for the background when the node isn't selected. */
    protected Color backgroundNonSelectionColor;

    /** Color to use for the focus indicator when the node has focus. */
    protected Color borderSelectionColor;

    private boolean isDropCell;
    private boolean fillBackground;

    /**
     * Set to true after the constructor has run.
     */
    private boolean inited;

    /**
     * Creates a {@code DefaultTreeCellRenderer}. Icons and text color are
     * determined from the {@code UIManager}.
     */
    public MyTreeCellRenderer() {
        inited = true;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.7
     */
    public void updateUI() {
        super.updateUI();
        // To avoid invoking new methods from the constructor, the
        // inited field is first checked. If inited is false, the constructor
        // has not run and there is no point in checking the value. As
        // all look and feels have a non-null value for these properties,
        // a null value means the developer has specifically set it to
        // null. As such, if the value is null, this does not reset the
        // value.
        if (!inited || (getLeafIcon() instanceof UIResource)) {
            setLeafIcon(DefaultLookup.getIcon(this, ui, "Tree.leafIcon"));
        }
        if (!inited || (getClosedIcon() instanceof UIResource)) {
            setClosedIcon(DefaultLookup.getIcon(this, ui, "Tree.closedIcon"));
        }
        if (!inited || (getOpenIcon() instanceof UIManager)) {
            setOpenIcon(DefaultLookup.getIcon(this, ui, "Tree.openIcon"));
        }
        if (!inited || (getTextSelectionColor() instanceof UIResource)) {
            setTextSelectionColor(
                    DefaultLookup.getColor(this, ui, "Tree.selectionForeground"));
        }
        if (!inited || (getTextNonSelectionColor() instanceof UIResource)) {
            setTextNonSelectionColor(
                    DefaultLookup.getColor(this, ui, "Tree.textForeground"));
        }
        if (!inited || (getBackgroundSelectionColor() instanceof UIResource)) {
            setBackgroundSelectionColor(
                    DefaultLookup.getColor(this, ui, "Tree.selectionBackground"));
        }
        if (!inited ||
                (getBackgroundNonSelectionColor() instanceof UIResource)) {
            setBackgroundNonSelectionColor(
                    DefaultLookup.getColor(this, ui, "Tree.textBackground"));
        }
        if (!inited || (getBorderSelectionColor() instanceof UIResource)) {
            setBorderSelectionColor(
                    DefaultLookup.getColor(this, ui, "Tree.selectionBorderColor"));
        }
        drawsFocusBorderAroundIcon = DefaultLookup.getBoolean(
                this, ui, "Tree.drawsFocusBorderAroundIcon", false);
        drawDashedFocusIndicator = DefaultLookup.getBoolean(
                this, ui, "Tree.drawDashedFocusIndicator", false);

        fillBackground = DefaultLookup.getBoolean(this, ui, "Tree.rendererFillBackground", true);
        Insets margins = DefaultLookup.getInsets(this, ui, "Tree.rendererMargins");
        if (margins != null) {
            setBorder(new EmptyBorder(margins.top, margins.left,
                    margins.bottom, margins.right));
        }

        setName("Tree.cellRenderer");
    }


    /**
     * Returns the default icon, for the current laf, that is used to
     * represent non-leaf nodes that are expanded.
     */
    public Icon getDefaultOpenIcon() {
        return DefaultLookup.getIcon(this, ui, "Tree.openIcon");
    }

    /**
     * Returns the default icon, for the current laf, that is used to
     * represent non-leaf nodes that are not expanded.
     */
    public Icon getDefaultClosedIcon() {
        return DefaultLookup.getIcon(this, ui, "Tree.closedIcon");
    }

    /**
     * Returns the default icon, for the current laf, that is used to
     * represent leaf nodes.
     */
    public Icon getDefaultLeafIcon() {
        return DefaultLookup.getIcon(this, ui, "Tree.leafIcon");
    }

    /**
     * Sets the icon used to represent non-leaf nodes that are expanded.
     */
    public void setOpenIcon(Icon newIcon) {
        openIcon = newIcon;
    }

    /**
     * Returns the icon used to represent non-leaf nodes that are expanded.
     */
    public Icon getOpenIcon() {
        return openIcon;
    }

    /**
     * Sets the icon used to represent non-leaf nodes that are not expanded.
     */
    public void setClosedIcon(Icon newIcon) {
        closedIcon = newIcon;
    }

    /**
     * Returns the icon used to represent non-leaf nodes that are not
     * expanded.
     */
    public Icon getClosedIcon() {
        return closedIcon;
    }

    /**
     * Sets the icon used to represent leaf nodes.
     */
    public void setLeafIcon(Icon newIcon) {
        leafIcon = newIcon;
    }

    /**
     * Returns the icon used to represent leaf nodes.
     */
    public Icon getLeafIcon() {
        return leafIcon;
    }

    /**
     * Sets the color the text is drawn with when the node is selected.
     */
    public void setTextSelectionColor(Color newColor) {
        textSelectionColor = newColor;
    }

    /**
     * Returns the color the text is drawn with when the node is selected.
     */
    public Color getTextSelectionColor() {
        return textSelectionColor;
    }

    /**
     * Sets the color the text is drawn with when the node isn't selected.
     */
    public void setTextNonSelectionColor(Color newColor) {
        textNonSelectionColor = newColor;
    }

    /**
     * Returns the color the text is drawn with when the node isn't selected.
     */
    public Color getTextNonSelectionColor() {
        return textNonSelectionColor;
    }

    /**
     * Sets the color to use for the background if node is selected.
     */
    public void setBackgroundSelectionColor(Color newColor) {
        backgroundSelectionColor = newColor;
    }


    /**
     * Returns the color to use for the background if node is selected.
     */
    public Color getBackgroundSelectionColor() {
        return backgroundSelectionColor;
    }

    /**
     * Sets the background color to be used for non selected nodes.
     */
    public void setBackgroundNonSelectionColor(Color newColor) {
        backgroundNonSelectionColor = newColor;
    }

    /**
     * Returns the background color to be used for non selected nodes.
     */
    public Color getBackgroundNonSelectionColor() {
        return backgroundNonSelectionColor;
    }

    /**
     * Sets the color to use for the border.
     */
    public void setBorderSelectionColor(Color newColor) {
        borderSelectionColor = newColor;
    }

    /**
     * Returns the color the border is drawn.
     */
    public Color getBorderSelectionColor() {
        return borderSelectionColor;
    }

    /**
     * Subclassed to map <code>FontUIResource</code>s to null. If
     * <code>font</code> is null, or a <code>FontUIResource</code>, this
     * has the effect of letting the font of the JTree show
     * through. On the other hand, if <code>font</code> is non-null, and not
     * a <code>FontUIResource</code>, the font becomes <code>font</code>.
     */
    public void setFont(Font font) {
        if(font instanceof FontUIResource)
            font = null;
        super.setFont(font);
    }

    /**
     * Gets the font of this component.
     * @return this component's font; if a font has not been set
     * for this component, the font of its parent is returned
     */
    public Font getFont() {
        Font font = super.getFont();

        if (font == null && tree != null) {
            // Strive to return a non-null value, otherwise the html support
            // will typically pick up the wrong font in certain situations.
            font = tree.getFont();
        }
        return font;
    }

    /**
     * Subclassed to map <code>ColorUIResource</code>s to null. If
     * <code>color</code> is null, or a <code>ColorUIResource</code>, this
     * has the effect of letting the background color of the JTree show
     * through. On the other hand, if <code>color</code> is non-null, and not
     * a <code>ColorUIResource</code>, the background becomes
     * <code>color</code>.
     */
    public void setBackground(Color color) {
        if(color instanceof ColorUIResource)
            color = null;
        super.setBackground(color);
    }

    /**
     * Configures the renderer based on the passed in components.
     * The value is set from messaging the tree with
     * <code>convertValueToText</code>, which ultimately invokes
     * <code>toString</code> on <code>value</code>.
     * The foreground color is set based on the selection and the icon
     * is set based on the <code>leaf</code> and <code>expanded</code>
     * parameters.
     */
    public Component getTreeCellRendererComponent(JTree tree, Object value,
                                                  boolean sel,
                                                  boolean expanded,
                                                  boolean leaf, int row,
                                                  boolean hasFocus) {
        String         stringValue = tree.convertValueToText(value, sel,
                expanded, leaf, row, hasFocus);

        this.tree = tree;
        this.hasFocus = hasFocus;
        setText(stringValue);

        Color fg = null;
        isDropCell = false;

        JTree.DropLocation dropLocation = tree.getDropLocation();
        if (dropLocation != null
                && dropLocation.getChildIndex() == -1
                && tree.getRowForPath(dropLocation.getPath()) == row) {

            Color col = DefaultLookup.getColor(this, ui, "Tree.dropCellForeground");
            if (col != null) {
                fg = col;
            } else {
                fg = getTextSelectionColor();
            }

            isDropCell = true;
        } else if (sel) {
            fg = getTextSelectionColor();
        } else {
            fg = getTextNonSelectionColor(value);
        }

        setForeground(fg);

        Icon icon = null;
        if (leaf) {
            icon = getLeafIcon();
        } else if (expanded) {
            icon = getOpenIcon();
        } else {
            icon = getClosedIcon();
        }

        if (!tree.isEnabled()) {
            setEnabled(false);
            LookAndFeel laf = UIManager.getLookAndFeel();
            Icon disabledIcon = laf.getDisabledIcon(tree, icon);
            if (disabledIcon != null) icon = disabledIcon;
            setDisabledIcon(icon);
        } else {
            setEnabled(true);
            setIcon(icon);
        }
        setComponentOrientation(tree.getComponentOrientation());

        selected = sel;

        // 根据节点的Visible控制隐藏，达到过滤的效果
        if( !isNodeVisible( (DefaultMutableTreeNode)value ) ) {
            // 隐藏原理就是把高宽设置为0，这样ui上就看不到了
            setPreferredSize(new Dimension(0, 0));
        }
        else {
            setPreferredSize(new Dimension(stringValue.length() * 6 + Math.round(stringValue.length()/2), 20));
        }

        return this;
    }

    /**
     * 检测是否需要展示
     * @param node
     * @return
     */
    private boolean isNodeVisible(DefaultMutableTreeNode node) {
        Object entity = node.getUserObject();
        if (entity instanceof UselessTreeNodeEntity) {
            return ((UselessTreeNodeEntity) entity).isVisible();
        }
        return true;
    }

    /**
     * 返回节点文本的颜色，根据检查结果修改底色
     * @return Color
     */
    public Color getTextNonSelectionColor(Object value) {
        Color color = this.getColor(value);
        if (color != null) {
            // 把底色修改一下
            this.backgroundNonSelectionColor = color;
        } else {
            // 非预期情况，改回初始值
            this.backgroundNonSelectionColor = DefaultLookup.getColor(this, ui, "Tree.textBackground");
        }
        // 字体颜色不改
        return getTextNonSelectionColor();
    }

    /**
     * 根据节点中保存的对象返回颜色
     * @param value 传入的节点对象
     * @return Color
     */
    private Color getColor(Object value) {
        Object entity = ((DefaultMutableTreeNode) value).getUserObject();
        if (entity instanceof UselessTreeNodeEntity) {
            switch (((UselessTreeNodeEntity)entity).color) {
                case "red":
                    return new Color(200, 0, 100); //红色，标识经过验证大概率存在
                case "magenta":
                    return new Color(150, 0, 200); //粉色，标识可能存在
                case "yellow":
                    return new Color(200, 200, 0); //黄色，标识跟外部存在交互的
                case "green":
                    return new Color(0, 200, 0); //绿色，标识资源类
            }
        }
        return null;
    }

    /**
     * Paints the value.  The background is filled based on selected.
     */
    public void paint(Graphics g) {
        Color bColor;

        if (isDropCell) {
            bColor = DefaultLookup.getColor(this, ui, "Tree.dropCellBackground");
            if (bColor == null) {
                bColor = getBackgroundSelectionColor();
            }
        } else if (selected) {
            bColor = getBackgroundSelectionColor();
        } else {
            bColor = getBackgroundNonSelectionColor();
            if (bColor == null) {
                bColor = getBackground();
            }
        }

        int imageOffset = -1;
        if (bColor != null && fillBackground) {
            imageOffset = getLabelStart();
            g.setColor(bColor);
            if(getComponentOrientation().isLeftToRight()) {
                g.fillRect(imageOffset, 0, getWidth() - imageOffset,
                        getHeight());
            } else {
                g.fillRect(0, 0, getWidth() - imageOffset,
                        getHeight());
            }
        }

        if (hasFocus) {
            if (drawsFocusBorderAroundIcon) {
                imageOffset = 0;
            }
            else if (imageOffset == -1) {
                imageOffset = getLabelStart();
            }
            if(getComponentOrientation().isLeftToRight()) {
                paintFocus(g, imageOffset, 0, getWidth() - imageOffset,
                        getHeight(), bColor);
            } else {
                paintFocus(g, 0, 0, getWidth() - imageOffset, getHeight(), bColor);
            }
        }
        super.paint(g);
    }

    private void paintFocus(Graphics g, int x, int y, int w, int h, Color notColor) {
        Color       bsColor = getBorderSelectionColor();

        if (bsColor != null && (selected || !drawDashedFocusIndicator)) {
            g.setColor(bsColor);
            g.drawRect(x, y, w - 1, h - 1);
        }
        if (drawDashedFocusIndicator && notColor != null) {
            if (treeBGColor != notColor) {
                treeBGColor = notColor;
                focusBGColor = new Color(~notColor.getRGB());
            }
            g.setColor(focusBGColor);
            BasicGraphicsUtils.drawDashedRect(g, x, y, w, h);
        }
    }

    private int getLabelStart() {
        Icon currentI = getIcon();
        if(currentI != null && getText() != null) {
            return currentI.getIconWidth() + Math.max(0, getIconTextGap() - 1);
        }
        return 0;
    }

    /**
     * Overrides <code>JComponent.getPreferredSize</code> to
     * return slightly wider preferred size value.
     */
    public Dimension getPreferredSize() {
        Dimension        retDimension = super.getPreferredSize();

        if(retDimension != null)
            retDimension = new Dimension(retDimension.width + 3,
                    retDimension.height);
        return retDimension;
    }

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void validate() {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     *
     * @since 1.5
     */
    public void invalidate() {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void revalidate() {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void repaint(long tm, int x, int y, int width, int height) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void repaint(Rectangle r) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     *
     * @since 1.5
     */
    public void repaint() {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    protected void firePropertyChange(String propertyName, Object oldValue, Object newValue) {
        // Strings get interned...
        if (propertyName == "text"
                || ((propertyName == "font" || propertyName == "foreground")
                && oldValue != newValue
                && getClientProperty(javax.swing.plaf.basic.BasicHTML.propertyKey) != null)) {

            super.firePropertyChange(propertyName, oldValue, newValue);
        }
    }

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, byte oldValue, byte newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, char oldValue, char newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, short oldValue, short newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, int oldValue, int newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, long oldValue, long newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, float oldValue, float newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, double oldValue, double newValue) {}

    /**
     * Overridden for performance reasons.
     * See the <a href="#override">Implementation Note</a>
     * for more information.
     */
    public void firePropertyChange(String propertyName, boolean oldValue, boolean newValue) {}

}
