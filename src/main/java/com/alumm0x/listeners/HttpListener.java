package com.alumm0x.listeners;

import burp.*;
import com.alumm0x.tree.MyTreeCellRenderer;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.tree.mouse.TreeMouseMune;
import com.alumm0x.ui.AnalysisUI;
import com.alumm0x.ui.RisksUI;
import com.alumm0x.ui.SettingUI;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpListener implements IHttpListener, IMessageEditorController {

    public HttpListener(){
        init(); //插件注册时执行插件初始化
    }

    /**
     * 插件初始化
     */
    private void init(){
        if (CommonStore.TREE == null){
            DefaultMutableTreeNode root = new DefaultMutableTreeNode("root"); // 默认根节点
            CommonStore.TREE = new JTree(root);
            CommonStore.TREE.setEditable(false); // 不允许编辑
            CommonStore.TREE.setRootVisible(false); // 不显示根节点
            CommonStore.TREEMODEL = CommonStore.TREE.getModel();
            // 获取树的根节点
            CommonStore.ROOTNODE = (DefaultMutableTreeNode) CommonStore.TREEMODEL.getRoot();

            CommonStore.TREE.addTreeSelectionListener(new TreeSelectionListener() {
                @Override
                public void valueChanged(TreeSelectionEvent e) {
                    // RisksUI.risksViewer.setMessage("".getBytes(StandardCharsets.UTF_8), false); // 清空信息
                    RisksUI.risksViewer.setText("".getBytes(StandardCharsets.UTF_8));
                    // 处理选中节点的信息初始化
                    DefaultMutableTreeNode n = (DefaultMutableTreeNode) e.getNewLeadSelectionPath().getLastPathComponent();
                    CommonStore.entity = (UselessTreeNodeEntity) n.getUserObject();
                    // JList更新数据必须通过setModel，重新设置数据
                    CommonStore.list.setModel(new AbstractListModel<String>() {
                        public int getSize() {
                            return CommonStore.entity.tabs.size();
                        }
                        public String getElementAt(int i) {
                            return CommonStore.entity.tabs.get(i);
                        }
                    });
                    // 设置选中行的请求及响应信息，有内容才添加
                    if (CommonStore.entity.getRequestResponse() != null) {
                        CommonStore.requestViewer.setMessage(CommonStore.entity.getRequestResponse().getRequest(), true);
                        CommonStore.responseViewer.setMessage(CommonStore.entity.getRequestResponse().getResponse(), false);
                        // 并添加pane
                        if (AnalysisUI.splitPane.getRightComponent() == null) {
                            AnalysisUI.splitPane.setRightComponent(AnalysisUI.tabs);
                        }
                    } else {
                        // 清空数据
                        CommonStore.requestViewer.setMessage("".getBytes(StandardCharsets.UTF_8), true);
                        CommonStore.responseViewer.setMessage("".getBytes(StandardCharsets.UTF_8), true);
                        // 并且删除pane
                        if (AnalysisUI.splitPane.getRightComponent() != null) {
                            AnalysisUI.splitPane.remove(AnalysisUI.tabs);
                        }
                    }
                    CommonStore.currentlyDisplayedItem = CommonStore.entity.getRequestResponse();
                    // 设置选中行的数据展示
                    //1.查询参数数据刷新
                    CommonStore.QUERY_TABLEMODEL.setMessages(BurpReqRespTools.getQueryMap(CommonStore.entity.getRequestResponse()));
                    CommonStore.foldTableComponent_query.updateButtonName(); //更新按钮的文字，增加数据条数
                    //2.自定义的请求及响应头信息
                    CommonStore.REQHEADER_TABLEMODEL.setMessages(CommonStore.entity.reqHeaders_custom);
                    CommonStore.foldTableComponent_reqheader.updateButtonName(); //更新按钮的文字，增加数据条数
                    CommonStore.RESPHEADER_TABLEMODEL.setMessages(CommonStore.entity.respHeaders_custom);
                    CommonStore.foldTableComponent_respheader.updateButtonName(); //更新按钮的文字，增加数据条数
                    //3.会话凭证信息，如cookie/jwt/token
                    CommonStore.SESSION_TABLEMODEL.setMessages(CommonStore.entity.credentials);
                    CommonStore.foldTableComponent_session.updateButtonName(); //更新按钮的文字，增加数据条数
                    //4.可能的安全风险
                    CommonStore.RISKS_TABLEMODEL.setMessages(CommonStore.entity.risks);
                    // 选中前还原RisksUI状态，删除tab、清空数据
                    if (RisksUI.splitPane.getRightComponent() != null) {
                        RisksUI.splitPane.remove(RisksUI.riskViewPane);
                    }
                }
            });
            // 右击菜单
            CommonStore.TREE.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    // 限制右击
                    if (SwingUtilities.isRightMouseButton(e)) {
                        TreePath path = CommonStore.TREE.getPathForLocation ( e.getX (), e.getY () );
                        Rectangle pathBounds = CommonStore.TREE.getUI ().getPathBounds ( CommonStore.TREE, path );
                        if ( pathBounds != null && pathBounds.contains (e.getX(), e.getY()) && path != null ) {
                            JPopupMenu menu = TreeMouseMune.getMune(path);
                            menu.show (CommonStore.TREE, pathBounds.x, pathBounds.y + pathBounds.height);
                        }
                    }
                }
            });
            CommonStore.TREE.setCellRenderer(new MyTreeCellRenderer());
        }
        // 初始化，默认这几个黑名单
        CommonStore.CUSTOMIZE_SUFFIX.add("font/");
        CommonStore.CUSTOMIZE_SUFFIX.add("image/");
        CommonStore.CUSTOMIZE_SUFFIX.add("text/css");
        CommonStore.CUSTOMIZE_SUFFIX.add(".js");
    }

    // 请求类型黑名单，不采集起信息
    private boolean isBlack(IHttpRequestResponse messageInfo) {
        for (String pruffix : CommonStore.CUSTOMIZE_SUFFIX) {
            // 检查黑名单后缀
            if (BurpReqRespTools.getUrlWithOutQuery(messageInfo).endsWith(pruffix)){
                return true;
            }
            // 再检查响应的Content-type
            for (String header : BurpReqRespTools.getRespHeaders(messageInfo)) {
                String kv = header.split(":")[1].trim();
                if (kv.startsWith(pruffix.trim())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest && CommonStore.ON_OFF && !isBlack(messageInfo)) {
            if (toolFlag == 4) {//proxy4/spider8/scanner16
                // 修改响应的referer-prolicy，以便让所有请求都带referer
                if (!Objects.equals(SettingUI.comboBox.getSelectedItem(), "默认目标de设置")) {
                    byte[] body = changeReferrerPolicy(messageInfo);
                    if (body != null) {
                        // 将修改的响应重新返回到请求中，返回给浏览器
                        messageInfo.setResponse(body);
                    }
                }
                // 更新请求树
                refreshTree(messageInfo);
            }
        }
    }

    /**
     * 修改Referrer-Policy为unsafe-url，这样referer任何情况都会携带
     */
    // TODO 还有些bug，有些网站加了后就加载不完整了
    public byte[] changeReferrerPolicy(IHttpRequestResponse messageInfo) {
        String key = (String) SettingUI.comboBox.getSelectedItem();
        IResponseInfo responseInfo = CommonStore.helpers.analyzeResponse(messageInfo.getResponse());
        List<String> headers = responseInfo.getHeaders();
        headers.remove(0); // 删除状态行，不然下面splite取值会越界
        for (String header : headers) {
            if (header.toLowerCase().startsWith("content-type")){
                String kv = header.split(":")[1].trim();
                if (kv.toLowerCase().startsWith("text/html")){
                    String body = new String(messageInfo.getResponse());
                    if (body.contains("name=\"referrer\"")){
                        Pattern referer = Pattern.compile("<meta.*?name=[\"']referrer[\"'].*?>");
                        Matcher matcher = referer.matcher(body);
                        if (matcher.find()){
                            return body.replace(matcher.group(), "<meta content=\"" + key + "\" name=\"referrer\">").getBytes(StandardCharsets.UTF_8);
                        }
                    } else {
                        return body.replace("<head>", "<head>\n<meta content=\"" + key + "\" name=\"referrer\">").getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
        }
        return null;
    }

    /**
     * 更新树，向树中添加节点
     * @param requestResponse 待添加到节点的对象
     */
    public void refreshTree(IHttpRequestResponse requestResponse) {
        UselessTreeNodeEntity entity = new UselessTreeNodeEntity(requestResponse);
        // 按域名添加node在根节点下，其他节点的正常跟踪
        DefaultMutableTreeNode scoprNode = addNodeByDomain(entity);
        // 根据黑名单控制后续节点的isVisible，如果是黑名单的，就下面所有添加的节点都是isVisible=false
        entity.setVisible(((UselessTreeNodeEntity)scoprNode.getUserObject()).isVisible());
        // 先检查对象是否已存在树中
        DefaultMutableTreeNode in = findNodeIn(CommonStore.ROOTNODE, entity);
        // 不存在的才进行添加
        if (in == null) {
            // 找到当前请求的来源页面，也就是其父节点，并添加子节点
            // bug:仅比较current跟referer只能获取到可能的父节点
            DefaultMutableTreeNode parent = findNodeByReferer(CommonStore.ROOTNODE, entity);
            if (parent == null) {
                // 有可能存在referer，但referer还没有请求过，也就是没流量所以树中没有节点，这里加个空节点，等后面请求了在进行初始化
                if (!entity.getReferer().equals("root")) {
                    // 存在referer，则构造空节点
                    UselessTreeNodeEntity empty = new UselessTreeNodeEntity();
                    // 将referer设置为current
                    empty.setCurrent(entity.getReferer());
                    // 直接向根节点添加子节点及子节点的子节点，因为也没办法再往上找了，empty是新增的当前请求的父节点，所以root/empty/entity
                    addNode(CommonStore.ROOTNODE, empty, entity);
                } else {
                    // 不存在树中且没有referer就向根节点添加子节点
                    addNode(CommonStore.ROOTNODE, entity);
                }
            } else {
                // 向该节点添加子节点
                addNode(parent, entity);
            }
            // 如果该请求是30x，则在上面添加的节点下建一个空子节点
            handlerRedirect(entity);
        } else {
            // 解决连续30x的请求，就需要持续往下新增子节点
            handlerRedirect(entity);
            // 如果已经存在节点了，则更新内容
            // 这里也是为了下面30x添加的空节点进行初始化
            ((UselessTreeNodeEntity)in.getUserObject()).setRequestResponse(requestResponse);
        }
        // 展开根节点下的所有节点(不展开所有了，自己选择展开吧)
        // expandAllNodes(new TreePath(CommonStore.ROOTNODE), true);
        CommonStore.TREE.expandPath(new TreePath(CommonStore.ROOTNODE)); // 默认根节点展开
        //当树节点重新加载后需调用此方法刷新树节点，否则树节点还是显示的未改变之前的
        //jTree.updateUI();直接调用会出现空指针问题
        //解决办法：不能直接调用updateUI方法，需要放到SwingUtilities.invokeLater中执行；
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                CommonStore.TREE.updateUI();
            }
        });
    }

    /**
     * 处理30x情况的节点新增处理，因为有多处大调用，所以封装成函数
     * @param entity 当前请求的对象
     */
    public void handlerRedirect(UselessTreeNodeEntity entity) {
        // 如果该请求是30x，则在上面添加的节点下建一个空子节点
        if (!entity.getLocation().equals("")) {
            UselessTreeNodeEntity empty = new UselessTreeNodeEntity();
            // 将location地址设置为current，因为30x后肯定还会有个请求的，其current就是location
            empty.setCurrent(entity.getLocation());
            // 设置referer为上一个节点的current
            // bug:这里会有个问题，重定向后的请求referer可能会带也可能不带，怎么处理？？（30x一般是不带的，如果是js发起的请求可能会带）
            // fix:30x一般referer的值是https://xx.com，或者是没有，各浏览器未来可能趋向30x不带referer！！
            //     一般如果带的话，referer也是跟父节点所在的页面的，所以这里保持跟父节点一致
            //     不保持一致的话，重定向后的请求就无法填充到这个节点，也就看不到详情了
            empty.setReferer(entity.getReferer());
            // 找到当前请求的节点，并添加子节点，其实就是找父节点
            DefaultMutableTreeNode t = findNodeIn(CommonStore.ROOTNODE, entity);
            if (t == null) {
                // 找不到就向根节点添加子节点
                addNode(CommonStore.ROOTNODE, empty);
            } else {
                // 向该节点添加子节点
                addNode(t, empty);
                // 因为存在重定向，所以可能存在重定向漏洞，先打个tag(重定向方式：location/meta标签/js控制)
                ((UselessTreeNodeEntity)t.getUserObject()).addTag("redirect-30x");
            }
        }
    }

    /**
     * 展开/折叠指定根节点下的所有节点，如果是跟节点，则折叠到子节点即可，因为跟节点隐藏了，再折叠就没了
     * @param parent 根节点
     * @param expand 展开与否
     */
    public static void expandAllNodes(TreePath parent, boolean expand) {
        TreeNode node = (TreeNode) parent.getLastPathComponent();
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements();) {
                TreeNode n = (TreeNode) e.nextElement(); // 获取父节点的子节点
                TreePath path = parent.pathByAddingChild(n); // 父节点path拼接子节点
                expandAllNodes(path, expand); // 递归子节点，设置展开
            }
        }
        if (expand) {
            CommonStore.TREE.expandPath(parent); //设置父节点
        } else {
            // 跟节点不折叠
            if (!parent.equals(new TreePath(CommonStore.ROOTNODE))) {
                CommonStore.TREE.collapsePath(parent);
            }
        }
    }

    /**
     * 向指定节点下添加子节点,并可以向子节点中再添加子节点
     * @param entity 需要添加的对象，一级子节点
     * @param childrens 二级子节点，也就是entity节点的子节点
     * @param rootNode 指定父节点
     */
    public void addNode(DefaultMutableTreeNode rootNode, UselessTreeNodeEntity entity, UselessTreeNodeEntity... childrens) {
        if (rootNode != null) {
            // 添加前检查rootNode的子节点中是否已存在了，存在就不添加了,这步是必须的，主要是emtpy的需要在检查是否添加，请求的entity就前面已经检查过了
            DefaultMutableTreeNode in = findNodeIn(rootNode, entity);
            if (in == null) {
                // 往根节点添加时需要进入
                if (Objects.equals(CommonStore.ROOTNODE, rootNode)) {
                    // 按域名添加node在根节点下，其他节点的正常跟踪,其实也可以算是父节点了
                    DefaultMutableTreeNode node = addNodeByDomain(entity);
                    // 将根节点替换为域名节点，这样无referer的都添加到对应域名下
                    if (node != null) {
                        rootNode = node;
                        // 这里不需要设置新节点的referer，因为主要是为了按域名归类
                    }
                }
                // 创建节点对象
                DefaultMutableTreeNode subNode = new DefaultMutableTreeNode(entity);
                // 追加节点到指定父节点
                rootNode.add(subNode);
                // 添加子节点
                for (UselessTreeNodeEntity e : childrens) {
                    // 同步子节点的父节点为entity
                    e.setReferer(entity.getCurrent());
                    addNode(subNode, e);
                }
            }
        }
    }

    /**
     * 向根节点添加域名节点，这样可以更好划分请求，没有referer的都添加到请求域名下的node
     * @param entity 需要添加的对象
     */
    public DefaultMutableTreeNode addNodeByDomain(UselessTreeNodeEntity entity) {
        if (CommonStore.ROOTNODE != null) {
            UselessTreeNodeEntity empty = new UselessTreeNodeEntity();
            // 通过正则获取url根部，用于构造网站的根节点
            String regex = "http[s]?://(.*?)/+";
            Pattern pattern = Pattern.compile(regex);
            Matcher m = pattern.matcher(entity.getCurrent());
            if (m.find()){
                empty.setCurrent(m.group());
                // 新增的domain节点需要判断下是否在黑名单,在则设置为false
                if (SettingUI.isBlackList(empty)) {
                    empty.setVisible(false);
                }
                // 添加前检查rootNode的子节点中是否已存在了，存在就不添加了
                DefaultMutableTreeNode in = null;
                // 仅遍历根节点下的子节点，不需要递归子节点的子节点
                for (Enumeration<?> e = CommonStore.ROOTNODE.children(); e.hasMoreElements(); ) {
                    // 获取当前节点保存的对象
                    DefaultMutableTreeNode n = (DefaultMutableTreeNode)e.nextElement();
                    UselessTreeNodeEntity et = (UselessTreeNodeEntity) n.getUserObject();
                    // 检查当前请求是否已经添加节点了,要current根origin都一样，有可能已有的接口不同页面调用，也就是origin不同，这样的需要追加节点
                    if (et.getCurrent().equals(empty.getCurrent()) && et.getReferer().equals(empty.getReferer())) {
                        in = n;
                        break;
                    }
                }
                if (in == null) {
                    // 创建节点对象
                    DefaultMutableTreeNode subNode = new DefaultMutableTreeNode(empty);
                    // TODO 这里做网站基础信息收集的动作，如域名解析/开放端口
                    // 追加节点到指定父节点
                    CommonStore.ROOTNODE.add(subNode);
                    return subNode;
                } else {
                    return in;
                }
            } else {
                CommonStore.callbacks.printError("[addNodeByDomain] 正则未获取url根部,entity.getCurrent: " + entity.getCurrent());
            }
        }
        return  null;
    }

    /**
     * 遍历指定树根节点的所有子节点的current，找到匹配的节点并返回，这里只能匹配到可能的父节点
     * @param node 遍历的节点
     * @param entity 匹配的值
     * @return 可能的父节点
     */
    public static DefaultMutableTreeNode findNodeByReferer(DefaultMutableTreeNode node, UselessTreeNodeEntity entity) {
        // TODO bug: 树中位置主要是current跟referer决定的，也是根据这两个去找节点的，两个属性相等才能说是相同的
        //           当前只是比较了current，如果存在多个相同current的节点，就只是返回第一个，但仅比较一个属性是无法准确定到位节点的，怎么处理？？
        // 当前节点是否有子节点
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements(); ) {
                // 获取当前节点保存的对象
                DefaultMutableTreeNode n = (DefaultMutableTreeNode)e.nextElement();
                UselessTreeNodeEntity et = (UselessTreeNodeEntity) n.getUserObject();
                // 找到current与当前请求referer相同的节点,就返回该节点
                if (et.getCurrent().equals(entity.getReferer())) {
                    return n;
                } else {
                    DefaultMutableTreeNode n1 = findNodeByReferer(n, entity); //递归查询
                    // 为null则继续遍历
                    if (n1 != null){
                        return n1;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 遍历指定树根节点的所有子节点的current，找到匹配的节点并返回
     * @param node 遍历的节点
     * @param entity 匹配的值
     * @return 返回匹配的node
     */
    public static DefaultMutableTreeNode findNodeByCurrent(DefaultMutableTreeNode node, UselessTreeNodeEntity entity) {
        // 当前节点是否有子节点
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements(); ) {
                // 获取当前节点保存的对象
                DefaultMutableTreeNode n = (DefaultMutableTreeNode)e.nextElement();
                UselessTreeNodeEntity et = (UselessTreeNodeEntity) n.getUserObject();
                // 找到current与d当前请求origin相同的节点,就返回该节点
                if (et.getCurrent().equals(entity.getCurrent())) {
                    return n;
                } else {
                    DefaultMutableTreeNode n1 = findNodeByCurrent(n, entity); //递归查询
                    // 为null则继续遍历
                    if (n1 != null){
                        return n1;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 检查是否树中已含有该对象了,要current根referer都相同
     * @param node 指定遍历初始节点
     * @param entity 待查找的对象
     * @return in
     */
    public static DefaultMutableTreeNode findNodeIn(DefaultMutableTreeNode node, UselessTreeNodeEntity entity) {
        // 当前节点是否有子节点
        if (node.getChildCount() > 0) {
            for (Enumeration<?> e = node.children(); e.hasMoreElements(); ) {
                // 获取当前节点保存的对象
                DefaultMutableTreeNode n = (DefaultMutableTreeNode)e.nextElement();
                UselessTreeNodeEntity et = (UselessTreeNodeEntity) n.getUserObject();
                // 检查当前请求是否已经添加节点了,要current根origin都一样，有可能已有的接口不同页面调用，也就是origin不同，这样的需要追加节点
                if (et.getCurrent().equals(entity.getCurrent()) && et.getReferer().equals(entity.getReferer())) {
                    return n;
                } else {
                    DefaultMutableTreeNode n1 = findNodeIn(n, entity); //递归查询
                    // 为null则继续遍历
                    if (n1 != null){
                        return n1;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public IHttpService getHttpService() {
        return CommonStore.currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return CommonStore.currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return CommonStore.currentlyDisplayedItem.getResponse();
    }
}
