package com.alumm0x.tree;

import burp.*;

import com.alumm0x.scan.StaticScanEngine;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.ToolsUtil;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    public Map<String, StaticCheckResult> risks = new HashMap<>(); //默认空数据


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
            // 检查请求的类型，资源请求或业务请求(主要是跟外部有交互的)
            parserContentType();
            // 静态安全风险分析,仅分析存在交互的请求
            // if (!color.equals("") && !color.equalsIgnoreCase("green")) {
            //     parserRisks();
            //     // 存在可能的分析则改为粉色
            //     if (secs.size() > 0) {
            //         color = "magenta";
            //     }
            // }
            StaticScanEngine.StaticCheck(this);
        }
    }

    /**
     * 解析请求及响应头，并保存下来
     */
    private void parserHeaders() {
        for (Map.Entry<String, Object> entry : BurpReqRespTools.getReqHeadersToMap(requestResponse).entrySet()){
            // 保存非标的请求头
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
        // 保存非标的响应头
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
                        // 当然也有开发不规范的请求，如//path,而非//domain/path
                        Pattern pattern = Pattern.compile("[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+");
                        Matcher m = pattern.matcher(locationV);
                        if (m.find()) {
                            // 补充协议即可
                            this.location = "[GET] " + URI.create(BurpReqRespTools.getHttpService(this.requestResponse).getProtocol() + ":" + locationV).normalize();
                        } else {
                            // 不规范的url，如//path，补充域名端口
                            this.location = "[GET] " + URI.create(BurpReqRespTools.getHttpService(this.requestResponse).getProtocol() + "://" + BurpReqRespTools.getHttpService(this.requestResponse).getHost() + ":" + BurpReqRespTools.getHttpService(this.requestResponse).getPort() + "/" + locationV).normalize().toString().replace(":443/", "/").replace(":80/", "/");
                        }
                    } else {
                        // 使用URI.normalize归一化处理，处理多余的/
                        this.location = "[GET] " + URI.create(BurpReqRespTools.getHttpService(this.requestResponse).getProtocol() + "://" + BurpReqRespTools.getHttpService(this.requestResponse).getHost() + ":" + BurpReqRespTools.getHttpService(this.requestResponse).getPort() + "/" + locationV).normalize().toString().replace(":443/", "/").replace(":80/", "/");
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
        ToolsUtil.notInsideAdd(this.tabs,tag);
    }

    /**
     * 添加检查结果到安全风险模型中，以便展示
     * @param results List<StaticCheckResult>
     */
    public void addMap(List<StaticCheckResult> results) {      
        if (results != null) {
            for (StaticCheckResult result : results) {
                // 直接put，已经存在的key会直接覆盖
                risks.put(result.desc, result);
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
