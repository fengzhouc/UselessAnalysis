package com.alumm0x.tree;

import burp.*;
import com.alumm0x.ui.SettingUI;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.risk.SecStaticCheck;
import com.alumm0x.util.risk.StaticCheckResult;

import java.net.URI;
import java.util.*;

/**
 * 树节点保存的对象，包含如下重要信息
 * origin: 当前请求开源页面的url,主要是referer/location，用于判定当前请求的父节点，以确定插入节点
 * current: 当前节点请求的url，用于UI展示
 * requestResponse: 当前请求的请求及响应信息，用于选中节点时展示其请求及响应信息
 *
 */
public class UselessTreeNodeEntity {

    private boolean isVisible = true; //默认都是需要展示的

    private String referer = "root"; //默认为空，也就是树的根节点，没有referer的都认为是根节点下的节点
    private String current = ""; // 用于在树结构中展示,可以从burp的req对象中获取
    private String location = ""; //保存该请求的location

    private IHttpRequestResponse requestResponse = null; // 请求信息，用于选中展示具体的请求及响应信息，用于UI展示

    public String color = ""; //节点底色设置，会根据检查结果设置 红red/黄yellow/绿green
    // 标签，存放的数据类型：自定义/数据类型/指纹
    public List<String> tabs = new ArrayList<>();

    //请求头参数，排除掉常规header，留下自定义的头，默认空
    public Map<String, Object> reqHeaders_custom = new HashMap<>();
    //响应头，排除掉常规header，留下自定义的头，默认空
    public Map<String, Object> respHeaders_custom = new HashMap<>();

    // 存放会话凭证信息
    public Map<String, Object> credentials = new HashMap<>(); //默认空数据
    // 存放可能的安全风险
    public Map<String, StaticCheckResult> secs = new HashMap<>(); //默认空数据
    // 存放poc验证成功的
    public Map<String, StaticCheckResult> pocs = new HashMap<>(); //默认空数据


    public UselessTreeNodeEntity() {
        this(null);
    }

    public UselessTreeNodeEntity(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            this.init(requestResponse);
        }
    }

    public void parser() {
        if (requestResponse != null) {
            // 会话凭证信息 cookie/token/jwt
            parserHeaders();
            //解析出banner
            parserBanner();
            // 筛出可能存在使用反序列化的请求
            parserSerialization();
            // 检查请求的类型，资源请求或业务请求(主要是跟外部有交互的)
            parserContentType();
            // 识别login/logout，打上标签
            parserLoginAndOut();
            // 识别文件上传请求，打上标签
            parserUpload();
            // 识别文件下载请求，打上标签
            parserDownload();
            // 是否websocket
            if (SecStaticCheck.isWebsocket(requestResponse)){
                addTag("websocket");
            }
            // 是否使用jwt
            if (SecStaticCheck.isJWT(requestResponse)){
                addTag("JWT");
            }
            // 静态安全风险分析,仅分析存在交互的请求
            if (!color.equals("") && !color.equalsIgnoreCase("green")) {
                parserRisks();
                // 存在可能的分析则改为粉色
                if (secs.size() > 0) {
                    color = "magenta";
                }
            }
        }
    }

    /**
     * 从请求中识别指纹，存入标签区
     */
    private void parserBanner() {
        IRequestInfo requestInfo = BurpReqRespTools.getRequestInfo(requestResponse);
        // Server指纹
        String server = SecStaticCheck.hasHdeader(BurpReqRespTools.getReqHeaders(requestResponse), "Server");
        if (server != null) {
            addTag(server);
        }
        // 匹配url，收集一份url
        String path = requestInfo.getUrl().getPath();
        List<String> banners = SourceLoader.loadSources("/banner/banners_url.oh");
        for (String banner : banners) {
            String[] kv = banner.split(",");
            if (kv[0].endsWith(path)) {
                addTag(kv[1]);
            }
        }
        // 匹配响应中的关键字
        List<String> banners_body = SourceLoader.loadSources("/banner/banners_body.oh");
        for (String banner : banners_body) {
            String[] kv = banner.split(",");
            // TODO 怎么查找
            if (kv[0].equalsIgnoreCase("")) {
                addTag(kv[1]);
            }
        }
        // 检测shiro的指纹
        String setCookie = SecStaticCheck.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null && setCookie.contains("rememberMe=")) {
            addTag("shiro");
        }
    }

    /**
     * 静态分析请求的安全风险
     */
    private void parserRisks() {
        // 安全风险分析
        // -安全响应头配置（太多了，基本都有，低危先忽略吧）
//        addMap(checkSecHeader(respHeaders));
        // -中间件版本
        addMap(SecStaticCheck.checkServer(requestResponse));
        // -重定向
        List<StaticCheckResult> rs = SecStaticCheck.checkRedirect(requestResponse);
        if (rs != null && rs.size() > 0){
            addTag("redirect");
            addMap(rs);
        }
        // -ssrf（请求和响应中是否有url的数据）
        List<StaticCheckResult> ssrf = SecStaticCheck.checkSsrf(requestResponse);
        if (ssrf != null && ssrf.size() > 0){
            addTag("ssrf");
            addMap(ssrf);
        }
        // -请求数据是json/xml的，根据tabs判断，列出需要验证的list
        addMap(SecStaticCheck.checkSerialization(tabs));
        // -csrf防护
        List<StaticCheckResult> csrf = SecStaticCheck.checkCsrf(requestResponse, reqHeaders_custom);
        if (csrf != null && csrf.size() > 0){
            addTag("csrf");
            addMap(csrf);
        }
        // -jsoncsrf防护
        List<StaticCheckResult> jsrf = SecStaticCheck.checkJsonCsrf(tabs, requestResponse);
        if (jsrf != null && jsrf.size() > 0){
            addTag("jsonCsrf");
            addMap(jsrf);
        }
        // -响应中的敏感信息
        List<StaticCheckResult> sens = SecStaticCheck.checkSensitiveInfo(requestResponse);
        if (sens != null && sens.size() > 0){
            addTag("可能存在敏感信息");
            addMap(sens);
        }
        // -CORS配置
        List<StaticCheckResult> cors = SecStaticCheck.checkCors(requestResponse);
        if (cors != null && cors.size() > 0){
            // cors仅在ajax请求有限制，form无法限制，所以如果是form就不提示cors了
            if (!tabs.contains("csrf")) {
                addTag("cors");
                addMap(cors);
            }
        }
        // 反射型xss的静态检测
        List<StaticCheckResult> xss = SecStaticCheck.checkReflectXss(requestResponse);
        if (xss != null && xss.size() > 0){
            addTag("reflectXss");
            addMap(xss);
        }
        // 登录相关请求追加安全要求提示验证
        addMap(SecStaticCheck.checkLoginAndout(tabs));
        // 文件上传相关请求追加安全要求提示验证
        addMap(SecStaticCheck.checkUpload(tabs));
        // -响应中的堆栈异常信息
        List<StaticCheckResult> err = SecStaticCheck.checkStraceError(requestResponse);
        if (err != null && err.size() > 0){
            addTag("可能存在堆栈异常");
            addMap(err);
        }
        // 检测请求参数中是否包含手机号或邮箱，可能存在轰炸风险
        List<StaticCheckResult> hong = SecStaticCheck.checkPhoneEmail(requestResponse);
        if (hong != null && hong.size() > 0){
            addTag("可能存在短信/邮箱轰炸");
            addMap(hong);
        }
        // -设计不合理的，如logout使用get
        List<StaticCheckResult> unsafe = SecStaticCheck.checkUnsfeDesignLoginout(tabs, requestResponse);
        if (unsafe != null && unsafe.size() > 0){
            addTag("可能的不安全设计");
            addMap(unsafe);
        }
        // 检测jsonp
        if (SecStaticCheck.isJsonp(requestResponse)){
            addTag("jsonp");
        }
    }


    /**
     * 识别登录跟登出的请求
     * 1.识别url特征，如login/logout
     * 2.识别响应头Set-Cookie，一般是登录登出的时候会有这类操作，当然排除不使用cookie作会话凭证的
     */
    private void parserLoginAndOut() {
        //1.识别url特征，如login/logout
        String url = BurpReqRespTools.getUrl(requestResponse);
        if (url.contains("login") || url.contains("logout")) {
            addTag("login/out");
        }
        //2.识别响应头Set-Cookie，一般是登录登出的时候会有这类操作，当然排除不使用cookie作会话凭证的
        String setCookie = SecStaticCheck.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null) {
            addTag("login/out");
        }
    }

    /**
     * 识别文件上传的请求
     * 1.识别content-type
     */
    private void parserUpload() {
        //识别请求头的contentype，文件上传的是multipart/
        String mul = SecStaticCheck.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Content-Type");
        if (mul != null && mul.equalsIgnoreCase("multipart/")) {
            addTag("upload");
        }
    }

    /**
     * 识别文件下载的请求
     * 1.识别content-type
     */
    private void parserDownload() {
        //识别是否有特征download
        if (this.current.contains("download")) {
            addTag("download");
        }
    }

    /**
     * 解析请求及响应头，并保存下来
     */
    private void parserHeaders() {
        for (Map.Entry<String, Object> entry : BurpReqRespTools.getReqHeadersToMap(requestResponse).entrySet()){
            if (!CommonStore.rfc_reqheader.contains(entry.getKey().toLowerCase())) {
                reqHeaders_custom.put(entry.getKey(), entry.getValue().toString());
            }
            // 将可能是会话凭证的头部保存下来
            switch (entry.getKey().toLowerCase()) {
                case "cookie":
                    credentials.put(entry.getKey(), entry.getValue().toString());
                case "www-authenticate":
                    credentials.put(entry.getKey(), entry.getValue().toString());
                default:
                    if (entry.getKey().toLowerCase().contains("token") || entry.getKey().toLowerCase().contains("auth")) {
                        credentials.put(entry.getKey(), entry.getValue().toString());
                    }
            }
        }
        if (credentials.size() != 0) {
            addTag("auth");
        }

        for (Map.Entry<String, String> entry : BurpReqRespTools.getRespHeadersToMap(requestResponse).entrySet()) {
            if (!CommonStore.rfc_reqheader.contains(entry.getKey().toLowerCase())) {
                respHeaders_custom.put(entry.getKey(), entry.getValue());
            }
        }
    }


    /**
     * 解析请求的类型，主要区分资源请求或业务请求
     * 判断依据：是否存在参数
     */
    private void parserContentType() {
        //1.先判定有没有请求参数，包含查询参数及body参数,没有的话就说明无外部交互，统一视为资源性，绿色
        if (BurpReqRespTools.getQuery(requestResponse) != null || BurpReqRespTools.getReqBody(requestResponse).length != 0) {
            //2.看请求方式，除了options/head/trace的请求
            if (!"OPTIONS/HEAD/TRACE".contains(BurpReqRespTools.getMethod(requestResponse))) {
                // 进到这里就已经是yellow了，有参数就存在交互
                color = "yellow";
            }
        } else {
            color = "green";
            // 没有常规的查询及body参数，则看下是否有请求头参数
            // 不过这样判断容易错，头部比较少有参数，一般是认证凭证，不过还是不放过吧
            if (reqHeaders_custom.size() != 0) {
                color = "yellow";
            }
        }
    }

    /**
     * 分析可能存在反序列化的请求
     */
    private void parserSerialization() {
        //看请求的contenttype，常规业务请求的返回数据类型json/xml，对应contenttype
        // json/xml可能存在反序列化，需要重点关注
        // 所以打个标签，后续好验证
        if (BurpReqRespTools.getReqBody(requestResponse).length > 0) {
            for (String header : BurpReqRespTools.getReqHeaders(requestResponse)) {
                if (header.trim().toLowerCase().startsWith("content-type")) {
                    String kv = header.split(":")[1].trim().toLowerCase();
                    if (kv.contains("json")) {
                        addTag("json");
                    } else if (kv.contains("xml")) {
                        addTag("xml");
                    }
                }
            }
        }
    }


    /**
     * 从响应中获取referer及location的值
     */
    private void init(IHttpRequestResponse requestResponse){
        this.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        //直接requestInfo.getUrl().toString()这样获取的url会带端口，标准端口也带，这样会导致跟location/referer无法匹配，所以把两个标准端口处理掉
        this.current = "[" + BurpReqRespTools.getMethod(this.requestResponse) + "] " + BurpReqRespTools.getUrl(this.requestResponse);
        // 获取当前请求的referer
        for (String header : BurpReqRespTools.getReqHeaders(this.requestResponse)) {
            if (header.toLowerCase().startsWith("referer:")) {
                this.referer = "[GET] " + header.split(":", 2)[1].trim();
                break;
            }
        }
        // 获取当前响应中的location
        for (String header : BurpReqRespTools.getRespHeaders(this.requestResponse)) {
            if (header.toLowerCase().startsWith("location:")) {
                String locationV = header.split(":", 2)[1].trim();
                // 处理同域下的30x，会是相对url，不带前面，所以处理成完整的
                if (!locationV.startsWith("http")) {
                    // 双斜杠开头是会跳转当前页面域名的该页面,一般这种是会有referer的
                    if (locationV.startsWith("//") && !this.getReferer().equals("root")) {
                        this.location = "[GET] " + URI.create(BurpReqRespTools.getHttpService(this.requestResponse).getProtocol() + "://" + BurpReqRespTools.getHttpService(this.requestResponse).getHost() + ":" + BurpReqRespTools.getHttpService(this.requestResponse).getPort() + locationV).normalize();
                    } else {
                        // 使用URI.normalize归一化处理，处理多余的/
                        this.location = "[GET] " + URI.create(BurpReqRespTools.getHttpService(this.requestResponse).getProtocol() + "://" + BurpReqRespTools.getHttpService(this.requestResponse).getHost() + ":" + BurpReqRespTools.getHttpService(this.requestResponse).getPort() + "/" + locationV).normalize().toString().replace(":443", "").replace(":80", "");
                    }
                } else {
                    this.location = "[GET] " + locationV;
                }
                // 标准化一下，如果location仅以?结尾，请求后的url后面会没有?了，这样设置current后，30x后的请求就不会匹配上，也就丢失跟踪了
                if (this.location.endsWith("?")) {
                    this.location = this.location.substring(0, location.length() - 2);
                }
                break;
            }
        }

        // 分析请求及响应
        parser();
    }

    /**
     * 添加tag的方法
     * @param tag
     */
    public void addTag(String tag) {
        SettingUI.notInsideAdd(this.tabs,tag);
        // 再添加到全局的tags中
        SettingUI.notInsideAdd(CommonStore.ALL_TAGS,tag);
    }

    /**
     * 添加检查结果到安全风险模型中，以便展示
     * @param results List<StaticCheckResult>
     */
    private void addMap(List<StaticCheckResult> results) {
        if (results != null) {
            for (StaticCheckResult result : results) {
                // 直接put，已经存在的key会直接覆盖
                secs.put(result.desc, result);
            }
        }
    }

    /**
     * 获取当前请求来源页面的url地址
     * @return String
     */
    public String getReferer() {
        return this.referer;
    }

    /**
     * 设置请求原来页面的url地址
     * @param origin String
     */
    public void setReferer(String origin) {
        this.referer = origin;
    }

    /**
     * 获取当前节点请求的url地址
     * @return String
     */
    public String getCurrent() {
        return this.current;
    }

    /**
     * 设置当前节点请求的url地址
     * @return String
     */
    public void setCurrent(String current) {
        this.current = current;
    }

    /**
     * 返回节点属性requestResponse，请求及响应信息
     * @return IHttpRequestResponsePersisted
     */
    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    /**
     * 返回节点属性requestResponse，请求及响应信息
     * @return IHttpRequestResponsePersisted
     */
    public void setRequestResponse(IHttpRequestResponse requestResponse) {
        if (requestResponse != null) {
            this.init(requestResponse);
        }
    }

    /**
     * 获取location
     * @return location；
     */
    public String getLocation() {
        return this.location;
    }

    /**
     * 设置location
     * @param location 重定向的url。绝对或相对都可
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * 节点的显示文本就是toString,否则会显示该对象的地址
     * @return String
     */
    public String toString(){
        return this.current;
    }


    public boolean isVisible() {
        return isVisible;
    }

    public void setVisible(boolean visible) {
        isVisible = visible;
    }
}
