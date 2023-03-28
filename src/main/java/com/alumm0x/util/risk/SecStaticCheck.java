package com.alumm0x.util.risk;


import burp.IHttpRequestResponse;
import burp.IParameter;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 封装漏洞检测的方法
 */
public class SecStaticCheck {

    /**
     * 检查安全响应头配置
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkSecHeader(IHttpRequestResponse requestResponse) {
        List<String> respHeaders = BurpReqRespTools.getRespHeaders(requestResponse);
        List<StaticCheckResult> results = new ArrayList<>();
        if (hasHdeader(respHeaders, "x-xss-protection") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-XSS-Protection";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 1;mode=block";
            results.add(result);
        }
        if (hasHdeader(respHeaders, "x-frame-options") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-Frame-Options";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 SAMEORIGIN";
            results.add(result);
        }
        if (hasHdeader(respHeaders, "x-content-type-options") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-Content-Type-Options";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 nosniff";
            results.add(result);
        }
        // HSTS这个支持不多，就不检测了
        // if (check(respHeaders, "http-strict-transport-security") != null) {}
        return results;
    }

    /**
     * 检查CORS跨域配置
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkCors(IHttpRequestResponse requestResponse) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        List<String> respHeaders = BurpReqRespTools.getRespHeaders(requestResponse);
        //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (hasHdeader(reqHeaders, "Cookie") != null){
            List<StaticCheckResult> results = new ArrayList<>();
            /*
             * ajax请求跨域获取数据的条件
             * 1、Access-Control-Allow-Credentials为true
             * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
             */
            if (hasHdeader(respHeaders, "Access-Control-Allow-Origin") != null){
                String origin_resp = hasHdeader(respHeaders, "Access-Control-Allow-Origin");
                String credentials = hasHdeader(respHeaders, "Access-Control-Allow-Credentials");
                if (credentials != null && credentials.contains("true")){
                    if (origin_resp.contains("*")) {
                        // 配置为*则允许任意跨域请求，存在风险
                        StaticCheckResult result = new StaticCheckResult();
                        result.desc = "任意跨域风险";
                        result.risk_param = origin_resp;
                        result.fix = "如需要跨域请求，则不要配置为* ，需根据业务场景，精确限制跨域范围；如不需要跨域，则Access-Control-Allow-Credentials配置为false。";
                        results.add(result);
                    }else {
                        String origin_req = hasHdeader(reqHeaders, "Origin");
                        // 请求头中存在Orgin，且origin的值相同
                        if (origin_req != null && origin_req.split(":", 2)[1].trim().equalsIgnoreCase(origin_resp.split(":", 2)[1].trim())) {
                            // 检查下是否为Origin请求头的值，如果是，则需要验证下是否动态设置，动态设置相当于允许任意跨域
                            StaticCheckResult result = new StaticCheckResult();
                            result.desc = "动态CORS风险";
                            result.risk_param = origin_req;
                            result.fix = "如需要跨域请求,需限制域名范围，如xxx.com主域名";
                            results.add(result);
                        }
                    }
                }
            }
            return results;
        }
        return null;
    }

    /**
     * 检查中间件版本信息
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkServer(IHttpRequestResponse requestResponse) {
        List<String> headers = BurpReqRespTools.getRespHeaders(requestResponse);
        String server = hasHdeader(headers, "Server");
        if (server != null) {
            // 获取Server的值，并以空格分割，一般版本都是/分隔的
            String[] sv = server.trim().split(":")[1].trim().split("/");
            if (sv.length >= 2) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "泄漏中间件版本";
                result.risk_param = server;
                result.fix = "建议隐藏Server的版本";
                results.add(result);
                return results;
            }
        }
        return null;
    }

    /**
     * 检查重定向风险
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkRedirect(IHttpRequestResponse requestResponse) {
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        //2.请求的url中含redirect敏感参数
        for (String query : querys.keySet()) {
            if (query.contains("redirect")
                    || query.contains("redirect_url")
                    || query.contains("redirect_uri")
                    || query.contains("callback")
                    || query.contains("url")
                    || query.contains("goto")
                    || query.contains("callbackIframeUrl")
            ) {
                Object value = querys.get(query);
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "任意重定向风险";
                result.risk_param = query + "=" + value;
                result.fix = "建议服务器端限制重定向的域名，设置白名单。";
                results.add(result);
                return results;
            }
        }
        return null;
    }

    /**
     * 检查ssrf,在参数中是否有url
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkSsrf(IHttpRequestResponse requestResponse) {
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        // ssrf就是需要传入完整的url，所以正则匹配请求参数
        String regex = "http[s]?://(.*?)[/&\"]+?[\\w/\\-\\._]*";
        List<StaticCheckResult> results = new ArrayList<>();
        //如果有body参数，需要多body参数进行测试
        if (reqBody.length > 0){
            String request_body_str = new String(reqBody);
            //检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(request_body_str);
            if (matcher.find()){//没匹配到则不进行后续验证
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "SSRF风险";
                result.risk_param = matcher.group(0);
                result.fix = "建议服务器端限制url的域名，设置白名单。";
                results.add(result);
                return results;
            }
        } else if (querys.size() > 0){
            //检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(querys.toString());
            if (matcher.find()){//没匹配到则不进行后续验证
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "SSRF风险";
                result.risk_param = matcher.group(0);
                result.fix = "建议服务器端限制重定向的域名，设置白名单。";
                results.add(result);
                return results;
            }
        }
        return null;
    }

    /**
     * 检查可能的反序列化
     * @param tabs 标签列表
     */
    public static List<StaticCheckResult> checkSerialization(List<String> tabs) {
        List<StaticCheckResult> results = new ArrayList<>();
        if (tabs.contains("json")) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "反序列漏洞风险-json";
            result.risk_param = "";
            result.fix = "根据实际漏洞进行修复。";
            results.add(result);
            return results;
        } else if (tabs.contains("xml")) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "反序列漏洞风险-xml";
            result.risk_param = "";
            result.fix = "根据实际漏洞进行修复。";
            results.add(result);
            return results;
        }
        return null;
    }

    /**
     * 检查csrf防护
     * @param requestResponse burp请求响应
     * @param reqHeaders_custom 非标请求头列表，包含可能的token
     *
     * 条件：
     * 1.form表单 (默认允许跨域)
     * 2.使用cookie
     * 3.是否有携带token
     */
    public static List<StaticCheckResult> checkCsrf(IHttpRequestResponse requestResponse,Map<String, Object> reqHeaders_custom) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (hasHdeader(reqHeaders, "Cookie") != null) {
            //要包含centen-type,且为form表单
            String ct = hasHdeader(reqHeaders, "Content-Type");
            if (ct != null && ct.contains("application/x-www-form-urlencoded") && reqBody.length > 0) {
                List<StaticCheckResult> results = new ArrayList<>();
                // 也不包含可能的token，这里就宽泛点，非标请求头为0就存在问题，因为key也不一定带token字样
                if (reqHeaders_custom.size() == 0) {
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "FORM表单CSRF风险";
                    result.risk_param = "";
                    result.fix = "建议增加csrf防护机制，如token令牌,form表单默认允许跨域";
                    results.add(result);
                    return results;
                } else {
                    for (String header : reqHeaders_custom.keySet()) {
                        // 没有携带token，常规关键字csrf
                        if (!header.toLowerCase().contains("csrf")) {
                            StaticCheckResult result = new StaticCheckResult();
                            result.desc = "FORM表单CSRF风险";
                            result.risk_param = "";
                            result.fix = "建议增加csrf防护机制，如token令牌,form表单默认允许跨域";
                            results.add(result);
                            return results;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * 检查Jsoncsrf防护
     * @param tabs 标签列表
     * @param requestResponse burp请求响应
     *
     * 条件：其实就是因为服务端没有限制centen-type，所以请求专程form提交
     * 1.json数据
     * 2.使用cookie
     * 3.后端没有限制content-type（这个是需要后续验证，满足上面三条就报问题了）
     */
    public static List<StaticCheckResult> checkJsonCsrf(List<String> tabs, IHttpRequestResponse requestResponse) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        if (tabs.contains("json") && hasHdeader(reqHeaders, "Cookie") != null && reqBody.length > 0) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "JsonCsrf风险";
                result.risk_param = "";
                result.fix = "修改为form的contenttype重放请求，修复建议: 后端接口限制contentType";
                results.add(result);
                return results;
        }
        return null;
    }

    /**
     * 检查响应中的敏感信息
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkSensitiveInfo(IHttpRequestResponse requestResponse) {
        byte[] body = BurpReqRespTools.getRespBody(requestResponse);
        // get请求获取数据才可能存在批量泄漏信息的可能，post/put/patch这种是更新数据，一般是单一用户信息
        // 有响应才检测
        if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")
                && body.length > 0) {
            String body_str = new String(body);
            String desc = "";
            //先检测是否存在url地址的参数，正则匹配
            String UIDRegex = "['\"&<;\\s/,][1-9]\\d{5}(18|19|([23]\\d))\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]['\"&<;\\s/,]"; //身份证的正则
            String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
            String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
            Pattern patternUID = Pattern.compile(UIDRegex);
            Pattern patternPhone = Pattern.compile(phoneRegex);
            Pattern patternEmail = Pattern.compile(emailRegex);
            Matcher matcherUid = patternUID.matcher(body_str);
            Matcher matcherPhone = patternPhone.matcher(body_str);
            Matcher matcherEmail = patternEmail.matcher(body_str);
            if (matcherUid.find()) {
                desc += "UID";
                desc += "\n" + matcherUid.group();
                while (matcherUid.find()) { //每次调用后会往后移
                    desc += "\n" + matcherUid.group();
                }
                desc += "\n";
            }
            if (matcherPhone.find()) {
                desc += "Phone";
                desc += "\n" + matcherPhone.group();
                while (matcherPhone.find()) { //每次调用后会往后移
                    desc += "\n" + matcherPhone.group();
                }
                desc += "\n";
            }
            if (matcherEmail.find()) {
                desc += "Email";
                desc += "\n" + matcherEmail.group();
                while (matcherEmail.find()) { //每次调用后会往后移
                    desc += "\n" + matcherEmail.group();
                }
                desc += "\n";
            }
            if (!desc.equals("")) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "敏感信息泄漏风险";
                result.risk_param = desc;
                result.fix = "如果业务不需要的数据可以不返回，如果需要的则服务端脱敏后再返回给客户端。";
                results.add(result);
                return results;
            }
        }
        return null;
    }

    /**
     * 给登录登出的请求提示安全要求并验证
     * @param tabs 标签列表
     */
    public static List<StaticCheckResult> checkLoginAndout(List<String> tabs) {
        // com.alumm0x.tree.UselessTreeNodeEntity.parserLoginAndOut里面会识别登录登出的请求，并打标签，所以这里识别标签就可以了
        if (tabs.contains("login/out")) {
            // 生成登录相关的风险提醒验证
            List<StaticCheckResult> results = new ArrayList<>();
            // 会话固定
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "是否会话固定";
            result.risk_param = "登录前后会话标识需要是变化的";
            result.fix = "";
            results.add(result);
            // 登出后失效session
            StaticCheckResult result1 = new StaticCheckResult();
            result1.desc = "登出后会话是否失效";
            result1.risk_param = "登出后需要失效会话，有些开发没有失效服务端的session，从而导致历史会话登出后还是可以用的";
            result1.fix = "";
            results.add(result1);
            // 会话超时登出
            StaticCheckResult result2 = new StaticCheckResult();
            result2.desc = "会话超时是否自动登出";
            result2.risk_param = "登录后，限制一段时间会话需要自动登出，超时时间建议：\\n\" +\n" +
                    "\"1.健康类业务：业务终端用户持续无操作<=12h\\n\" +\n" +
                    "\"2.其他业务：业务终端用户持续无操作<=14d";
            result2.fix = "";
            results.add(result2);
            // 是否有登出
            StaticCheckResult result3 = new StaticCheckResult();
            result3.desc = "是否有登出功能";
            result3.risk_param = "有登录就要有登出，有注册就要有注销，合规要求";
            result3.fix = "";
            results.add(result3);
            // 会话cookie安全属性
            StaticCheckResult result4 = new StaticCheckResult();
            result4.desc = "会话cookie安全属性";
            result4.risk_param = "会话cookie需要添加安全属性HttpOnly/Secure";
            result4.fix = "";
            results.add(result4);

            return results;
        }
        return null;
    }

    /**
     * 给文件上传的请求提示安全要求并验证
     * @param tabs 标签列表
     */
    public static List<StaticCheckResult> checkUpload(List<String> tabs) {
        // com.alumm0x.tree.UselessTreeNodeEntity.parserUpload里面会识别文件上传的请求，并打标签，所以这里识别标签就可以了
        if (tabs.contains("upload")) {
            // 生成上传相关的风险提醒验证
            List<StaticCheckResult> results = new ArrayList<>();
            // 类型限制
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "上传文件类型限制";
            result.risk_param = "是否根据业务需要限制上传文件类型";
            result.fix = "";
            results.add(result);
            // 大小限制
            StaticCheckResult result1 = new StaticCheckResult();
            result1.desc = "上传文件大小限制";
            result1.risk_param = "是否根据业务需要限制上传文件大小";
            result1.fix = "";
            results.add(result1);
            // webshell
            StaticCheckResult result2 = new StaticCheckResult();
            result2.desc = "上传webshell";
            result2.risk_param = "是否可以上传webshell";
            result2.fix = "";
            results.add(result2);

            return results;
        }
        return null;
    }

    /**
     * 检测是否存在异常上抛到用户侧
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkStraceError(IHttpRequestResponse requestResponse) {
        byte[] body = BurpReqRespTools.getRespBody(requestResponse);
        //如果有响应才检测
        if (body.length > 0) {
            String body_str = new String(body);
            String desc = "";
            //1.先关键字检测
            if (body_str.contains("Exception")) {
                desc += body_str;
            }
            // TODO 下面这里误报比较大，后面看看什么方法更精确匹配
//            else {
//                //2.没有关键字，再检测body是否存在堆栈异常，正则匹配
//                String ErrorRegex = "(\\w+\\.)+\\w+\\s*.*"; //java异常包路径的正则
//                Pattern patternERR = Pattern.compile(ErrorRegex);
//                Matcher matcherERR = patternERR.matcher(body_str);
//                if (matcherERR.find()) {
//                    desc += "ERROR";
//                    desc += "\n" + matcherERR.group();
//                    while (matcherERR.find()) { //每次调用后会往后移
//                        desc += "\n" + matcherERR.group();
//                    }
//                    desc += "\n";
//                }
//            }
            if (!desc.equals("")) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "异常堆栈信息泄露";
                result.risk_param = desc;
                result.fix = "异常堆栈信息会泄漏开发组件，应用理应处理好所有的异常，避免直接抛到用户侧";
                results.add(result);
                return results;
            }
        }
        return null;
    }

    /**
     * 检查请求参数中是否包含手机号及邮箱，可能是验证码获取的请求
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkPhoneEmail(IHttpRequestResponse requestResponse) {
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        String desc = "";
        String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
        String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
        Pattern patternPhone = Pattern.compile(phoneRegex);
        Pattern patternEmail = Pattern.compile(emailRegex);
        //如果有响应才检测
        if (reqBody.length > 0) {
            String body_str = new String(reqBody);
            //先检测是否存在url地址的参数，正则匹配
            Matcher matcherPhone = patternPhone.matcher(body_str);
            Matcher matcherEmail = patternEmail.matcher(body_str);
            if (matcherPhone.find()) {
                desc += "Phone";
                desc += "\n" + matcherPhone.group();
                while (matcherPhone.find()) { //每次调用后会往后移
                    desc += "\n" + matcherPhone.group();
                }
                desc += "\n";
            }
            if (matcherEmail.find()) {
                desc += "Email";
                desc += "\n" + matcherEmail.group();
                while (matcherEmail.find()) { //每次调用后会往后移
                    desc += "\n" + matcherEmail.group();
                }
                desc += "\n";
            }
        }
        if (querys.size() > 0) {
            for (Object value : querys.values()) {
                Matcher matcherPhone = patternPhone.matcher(value.toString());
                Matcher matcherEmail = patternEmail.matcher(value.toString());
                if (matcherPhone.find()) {
                    desc += "queryPhone";
                    desc += "\n" + matcherPhone.group();
                    while (matcherPhone.find()) { //每次调用后会往后移
                        desc += "\n" + matcherPhone.group();
                    }
                    desc += "\n";
                }
                if (matcherEmail.find()) {
                    desc += "queryEmail";
                    desc += "\n" + matcherEmail.group();
                    while (matcherEmail.find()) { //每次调用后会往后移
                        desc += "\n" + matcherEmail.group();
                    }
                    desc += "\n";
                }
            }
        }
        if (!desc.equals("")) {
            List<StaticCheckResult> results = new ArrayList<>();
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "短信/邮件轰炸风险";
            result.risk_param = desc;
            result.fix = "因为提交的数据中含有手机号或邮箱，可能是发送短信或邮件的接口";
            results.add(result);
            return results;
        }
        return null;
    }

    /**
     * 检查不安全设计-login/out使用get请求
     * @param tabs 标签列表
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkUnsfeDesignLoginout(List<String> tabs, IHttpRequestResponse requestResponse) {
        if (tabs.contains("login/out")) {
            if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("GET")) {
                if (BurpReqRespTools.getQuery(requestResponse) != null && (
                        BurpReqRespTools.getQuery(requestResponse).contains("username")
                        || BurpReqRespTools.getQuery(requestResponse).contains("password")
                )) {
                    List<StaticCheckResult> results = new ArrayList<>();
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "不安全设计-login/out使用GET方法";
                    result.risk_param = "登录登出不允许使用GET请求方式";
                    result.fix = "";
                    results.add(result);
                    return results;
                }
            }
        }
        return null;
    }


    /**
     * 检查头部是否包含某信息
     * @return 返回找到的头信息
     */
    public static String hasHdeader(List<String> headers, String header) {
        if (null == headers) {
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).startsWith(header.toLowerCase(Locale.ROOT))) {
                return s;
            }
        }
        return null;
    }

    /**
     * 静态检测jsonp
     * @return
     */
    public static boolean isJsonp(IHttpRequestResponse requestResponse){
        // 1.响应content-type需要是js
        if (hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "content-type") != null
                && hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "content-type").contains("/javascript")) {
            String resp = new String(BurpReqRespTools.getRespBody(requestResponse));
            for (Object queryvalue : BurpReqRespTools.getQueryMap(requestResponse).values()) {
                // fix: 现在返回的不一定是函数名开头了
                if (resp.contains(queryvalue + "(")){
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 静态检测websocket,检查是否包含相关请求头
     * @return
     */
    public static boolean isWebsocket(IHttpRequestResponse requestResponse){
        // 头部信息包含Upgrade
        return hasHdeader(BurpReqRespTools.getReqHeaders(requestResponse), "Sec-WebSocket-Key") != null;
    }

    /**
     * 检测是否使用jwt
     */
    public static boolean isJWT(IHttpRequestResponse requestResponse) {
        // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
        for (IParameter parameter : CommonStore.helpers.analyzeRequest(requestResponse).getParameters()) {
            byte[] decode = CommonStore.helpers.base64Decode(parameter.getValue());
            if (new String(decode).contains("\"alg\"")) {
                return true;
            }
        }
        // 检查请求头
        for (Object value : BurpReqRespTools.getReqHeadersToMap(requestResponse).values()) {
            byte[] decode = CommonStore.helpers.base64Decode(value.toString());
            if (new String(decode).contains("\"alg\"")) {
                return true;
            }
        }
        // 检查json数据
        if (BurpReqRespTools.getContentType(requestResponse).contains("application/json")
                && BurpReqRespTools.getReqBody(requestResponse).length > 0
                && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")){
            JsonTools tools = new JsonTools();
            try {
                tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse))), new ParamHandlerImpl() {
                    @Override
                    public List<ParamKeyValue> handler(Object key, Object value) {
                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"")) {
                            paramKeyValues.add(null); //匹配条件则返回bull，触发上层函数的空指针异常已反馈结果
                        } else {
                            paramKeyValues.add(new ParamKeyValue(key, value));
                        }
                        return paramKeyValues;
                    }
                });
            } catch (NullPointerException e) {
                // 出现空指针则说明匹配到条件
                return true;
            }
        }
        return false;
    }

}
