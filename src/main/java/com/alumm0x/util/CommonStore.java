package com.alumm0x.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.PocEntry;
import com.alumm0x.scan.ScanLoggerTable;
import com.alumm0x.scan.ScanLoggerTableModel;
import com.alumm0x.scan.http.OkHttpRequester;
import com.alumm0x.scan.http.task.*;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.ui.FoldTableComponent;
import com.alumm0x.ui.tablemodel.MyTableModel;
import com.alumm0x.ui.tablemodel.SecTableModel;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommonStore {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public static JTree TREE = null;
    public static DefaultMutableTreeNode ROOTNODE = null; //根节点
    public static TreeModel TREEMODEL = null;
    public static List<String> ALL_TAGS = new ArrayList<>(); //所有的标签
    public static boolean ON_OFF = false;
    public static List<String> CUSTOMIZE_SUFFIX = new ArrayList<>(); //允许的后缀
    public static List<String> TARGET_SCOPE = new ArrayList<>(); //允许的target,用于过滤TREE展示的数据

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
    public static FoldTableComponent foldTableComponent_sec; // 可能的安全风险的展示ui组件，用于刷新分类text数据
    public static SecTableModel SEC_TABLEMODEL = new SecTableModel(); //可能的安全风险的model，用于刷新数据
    //5.可能的安全风险
    public static FoldTableComponent foldTableComponent_poc; // 验证poc结果的展示ui组件，用于刷新分类text数据
    public static SecTableModel POC_TABLEMODEL = new SecTableModel(); //验证poc结果的model，用于刷新数据

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
        pocs.add(new PocEntry(IDOR.name,IDOR.comments));
        pocs.add(new PocEntry(Redirect.name, Redirect.comments));
        pocs.add(new PocEntry(Csrf.name,Csrf.comments));
        pocs.add(new PocEntry(JsonCsrf.name,JsonCsrf.comments));
        pocs.add(new PocEntry(BeanParamInject.name,BeanParamInject.comments));
        pocs.add(new PocEntry(BypassAuth.name,BypassAuth.comments));
        pocs.add(new PocEntry(WebSocketHijacking.name,WebSocketHijacking.comments));
        pocs.add(new PocEntry(Ssrf.name,Ssrf.comments));
        pocs.add(new PocEntry(UploadSecure.name,UploadSecure.comments));
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
    public static List<String> rfc_reqheader = new ArrayList<>();
    static {
        rfc_reqheader.add("accept");
        rfc_reqheader.add("accept-language");
        rfc_reqheader.add("accept-encoding");
        rfc_reqheader.add("accept-charset");
        rfc_reqheader.add("authorization");
        rfc_reqheader.add("cache-control");
        rfc_reqheader.add("connection");
        rfc_reqheader.add("accept-ch");
        rfc_reqheader.add("accept-patch");
        rfc_reqheader.add("accept-post");
        rfc_reqheader.add("accept-ranges");
        rfc_reqheader.add("access-control-allow-credentials");
        rfc_reqheader.add("access-control-allow-headers");
        rfc_reqheader.add("access-control-allow-methods");
        rfc_reqheader.add("access-control-allow-origin");
        rfc_reqheader.add("access-control-expose-headers");
        rfc_reqheader.add("access-control-max-age");
        rfc_reqheader.add("access-control-request-headers");
        rfc_reqheader.add("access-control-request-method");
        rfc_reqheader.add("age");
        rfc_reqheader.add("allow");
        rfc_reqheader.add("cache-control");
        rfc_reqheader.add("clear-site-data");
        rfc_reqheader.add("content-disposition");
        rfc_reqheader.add("content-language");
        rfc_reqheader.add("content-length");
        rfc_reqheader.add("content-location");
        rfc_reqheader.add("content-range");
        rfc_reqheader.add("content-security-policy");
        rfc_reqheader.add("content-security-policy-report-only");
        rfc_reqheader.add("content-type");
        rfc_reqheader.add("cookie");
        rfc_reqheader.add("cross-origin-embedder-policy");
        rfc_reqheader.add("cross-origin-opener-policy");
        rfc_reqheader.add("cross-origin-resource-policy");
        rfc_reqheader.add("date");
        rfc_reqheader.add("device-memory");
        rfc_reqheader.add("digest");
        rfc_reqheader.add("downlink");
        rfc_reqheader.add("early-data");
        rfc_reqheader.add("ect");
        rfc_reqheader.add("etag");
        rfc_reqheader.add("expect");
        rfc_reqheader.add("expect-ct");
        rfc_reqheader.add("expires");
        rfc_reqheader.add("forwarded");
        rfc_reqheader.add("from");
        rfc_reqheader.add("host");
        rfc_reqheader.add("if-match");
        rfc_reqheader.add("if-modified-since");
        rfc_reqheader.add("if-none-match");
        rfc_reqheader.add("if-range");
        rfc_reqheader.add("if-unmodified-since");
        rfc_reqheader.add("keep-alive");
        rfc_reqheader.add("last-modified");
        rfc_reqheader.add("link");
        rfc_reqheader.add("location");
        rfc_reqheader.add("max-forwards");
        rfc_reqheader.add("nel");
        rfc_reqheader.add("origin");
        rfc_reqheader.add("permissions-policy");
        rfc_reqheader.add("proxy-authenticate");
        rfc_reqheader.add("proxy-authorization");
        rfc_reqheader.add("range");
        rfc_reqheader.add("referer");
        rfc_reqheader.add("referrer-policy");
        rfc_reqheader.add("retry-after");
        rfc_reqheader.add("rtt");
        rfc_reqheader.add("save-data");
        rfc_reqheader.add("sec-ch-prefers-reduced-motion");
        rfc_reqheader.add("sec-ch-ua");
        rfc_reqheader.add("sec-ch-ua-arch");
        rfc_reqheader.add("sec-ch-ua-bitness");
        rfc_reqheader.add("sec-ch-ua-full-version-list");
        rfc_reqheader.add("sec-ch-ua-mobile");
        rfc_reqheader.add("sec-ch-ua-model");
        rfc_reqheader.add("sec-ch-ua-platform");
        rfc_reqheader.add("sec-ch-ua-platform-version");
        rfc_reqheader.add("sec-fetch-dest");
        rfc_reqheader.add("sec-fetch-mode");
        rfc_reqheader.add("sec-fetch-site");
        rfc_reqheader.add("sec-fetch-user");
        rfc_reqheader.add("sec-gpc");
        rfc_reqheader.add("sec-websocket-accept");
        rfc_reqheader.add("server");
        rfc_reqheader.add("server-timing");
        rfc_reqheader.add("service-worker-navigation-preload");
        rfc_reqheader.add("set-cookie");
        rfc_reqheader.add("sourcemap");
        rfc_reqheader.add("te");
        rfc_reqheader.add("timing-allow-origin");
        rfc_reqheader.add("trailer");
        rfc_reqheader.add("transfer-encoding");
        rfc_reqheader.add("upgrade");
        rfc_reqheader.add("upgrade-insecure-requests");
        rfc_reqheader.add("user-agent");
        rfc_reqheader.add("vary");
        rfc_reqheader.add("via");
        rfc_reqheader.add("want-digest");
        rfc_reqheader.add("www-authenticate");
        rfc_reqheader.add("x-content-security-policy");
        rfc_reqheader.add("x-content-type-options");
        rfc_reqheader.add("x-frame-options");
        rfc_reqheader.add("x-xss-protection");
        rfc_reqheader.add("http-strict-transport-security");
        rfc_reqheader.add("x-requested-with");

        rfc_reqheader.add("pragma");
    }
    //2.常规的响应头部,保存标准规范的头部名称，用来过滤出自定义的头部
    public static List<String> rfc_respheader = new ArrayList<>();
    static {
        rfc_respheader.add("accept-ch");
        rfc_respheader.add("accept-patch");
        rfc_respheader.add("accept-post");
        rfc_respheader.add("accept-ranges");
        rfc_respheader.add("access-control-allow-credentials");
        rfc_respheader.add("access-control-allow-headers");
        rfc_respheader.add("access-control-allow-methods");
        rfc_respheader.add("access-control-allow-origin");
        rfc_respheader.add("access-control-expose-headers");
        rfc_respheader.add("access-control-max-age");
        rfc_respheader.add("access-control-request-headers");
        rfc_respheader.add("access-control-request-method");
        rfc_respheader.add("age");
        rfc_respheader.add("allow");
        rfc_respheader.add("cache-control");
        rfc_respheader.add("clear-site-data");
        rfc_respheader.add("content-disposition");
        rfc_respheader.add("content-Language");
    }
}
