package com.alumm0x.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.PocEntry;
import com.alumm0x.scan.ScanEngine;
import com.alumm0x.scan.ScanLoggerTable;
import com.alumm0x.scan.ScanLoggerTableModel;
import com.alumm0x.scan.StaticScanEngine;
import com.alumm0x.scan.http.OkHttpRequester;
import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.ui.FoldTableComponent;
import com.alumm0x.ui.tablemodel.MyTableModel;
import com.alumm0x.ui.tablemodel.RisksTableModel;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeModel;
import java.util.ArrayList;
import java.util.List;

public class CommonStore {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public static JTree TREE = null;
    public static DefaultMutableTreeNode ROOTNODE = null; //根节点
    public static TreeModel TREEMODEL = null;
    public static List<String> VIEW_TAGS = new ArrayList<>(); //所有的标签
    public static boolean ON_OFF = false;
    public static List<String> CUSTOMIZE_SUFFIX = new ArrayList<>(); //允许的后缀
    public static List<String> TARGET_SCOPE = new ArrayList<>(); //允许的target,用于过滤TREE展示的数据
    public static List<String> REDIRECT_SCOPE = new ArrayList<>(); //重定向的参数
    static {
        REDIRECT_SCOPE.add("redirect");
        REDIRECT_SCOPE.add("redirect_url");
        REDIRECT_SCOPE.add("redirect_uri");
        REDIRECT_SCOPE.add("callback");
        REDIRECT_SCOPE.add("url");
        REDIRECT_SCOPE.add("goto");
        REDIRECT_SCOPE.add("callbackIframeUrl");
        REDIRECT_SCOPE.add("service");
    }

    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IHttpRequestResponse currentlyDisplayedItem; //当前请求的IHttpRequestResponse，用于获取IHttpService,不然无法发送给repeter等
    public static UselessTreeNodeEntity entity = new UselessTreeNodeEntity(); //存放当前选中节点的对象,默认一个空模型，为了ui的加载，刚开始的时候是没有的，会空指针然后UI加载不了

    // 信息展示区
    //1.标签list
    public static JList<String> list ;
    //2.查询参数
    public static FoldTableComponent foldTableComponent_query; // 查询参数的展示ui组件，用于刷新分类text数据
    public static MyTableModel QUERY_TABLEMODEL = new MyTableModel(); //查询参数的model，用于刷新数据
    //3.自定义的请求头及响应头
    public static FoldTableComponent foldTableComponent_reqheader; // 非标请求头的展示ui组件，用于刷新分类text数据
    public static MyTableModel REQHEADER_TABLEMODEL = new MyTableModel(); //非标请求头的model，用于刷新数据
    public static FoldTableComponent foldTableComponent_respheader; // 非标响应头的展示ui组件，用于刷新分类text数据
    public static MyTableModel RESPHEADER_TABLEMODEL = new MyTableModel(); //非标响应头的model，用于刷新数据
    //4.会话凭证
    public static FoldTableComponent foldTableComponent_session; // 可能的会话凭证的展示ui组件，用于刷新分类text数据
    public static MyTableModel SESSION_TABLEMODEL = new MyTableModel(); //可能的会话凭证的model，用于刷新数据
    //5.可能的安全风险
    public static RisksTableModel RISKS_TABLEMODEL = new RisksTableModel(); //可能的安全风险的model，用于刷新数据

    // scanlogger
    public static final List<LogEntry> log = new ArrayList<>();
    public static ScanLoggerTable logTable; //视图table对象
    public static ScanLoggerTableModel logModel; //数据模型
    public static IMessageEditor scan_requestViewer;
    public static IMessageEditor scan_responseViewer;

    // pocs detail
    public static final List<PocEntry> pocs = new ArrayList<>();
    public static JTable pocsTable; //视图table对象
    // 设置poc的解读数据
    static {
        for (Class<? extends StaticTaskImpl> task : StaticScanEngine.tasks) {
            try{
                pocs.add(new PocEntry(task.getSimpleName(),(String)task.getDeclaredField("comments").get(null)));
            } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                callbacks.printError(e.getMessage());
            }
        }
        for (Class<? extends TaskImpl> task : ScanEngine.tasks) {
            try{
                pocs.add(new PocEntry(task.getSimpleName(),(String)task.getDeclaredField("comments").get(null)));
            } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
                callbacks.printError(e.getMessage());
            }
        }
    }

    // 单例http发包器
    public static  OkHttpRequester okHttpRequester = OkHttpRequester.getInstance();

    // 静态字典
    //1.重点关注的响应数据类型
    public static List<String> ct = new ArrayList<>();
    static {
        ct.add("application/json");
        ct.add("application/xml");
        ct.add("text/xml");
        ct.add("application/xhtml+xml");
        ct.add("application/atom+xml");
        ct.add("application/octet-stream");
        ct.add("text/plain");
        ct.add("application/x-www-form-urlencoded ");
    }
    //2.常规的请求头部,保存标准规范的头部名称，用来过滤出自定义的头部
    public static List<String> rfc_reqheader = SourceLoader.loadSources("/rfc/rfc_reqheaders.bbm");
    
    //2.常规的响应头部,保存标准规范的头部名称，用来过滤出自定义的头部
    public static List<String> rfc_respheader = SourceLoader.loadSources("/rfc/rfc_respheaders.bbm");

    // 关于认证的请求头
    public static List<String> auth_header = SourceLoader.loadSources("/rfc/rfc_authheaders.bbm");

    // 关于websocket的请求头
    public static List<String> ws_reqheader = SourceLoader.loadSources("/rfc/rfc_wsheaders.bbm");

    // 关于cors的响应头
    public static List<String> cors_respheader = SourceLoader.loadSources("/rfc/rfc_corsheaders.bbm");

}
