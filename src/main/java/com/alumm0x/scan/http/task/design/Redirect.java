package com.alumm0x.scan.http.task.design;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Redirect extends TaskImpl  {

    public static String name = "Redirect";
    public static String comments = "任意重定向检测。会根据特征匹配可能影响重定向的参数，构造恶意数据，重访请求是否重定向地址与构造的一致。";
    public static String fix = "白名单限制重定向的地址，注意域名的获取需要准确，不然可能绕过限制";

    public boolean isBypass = false; //标记bypass，callback的时候可以判断
    public UselessTreeNodeEntity entity;

    public Redirect(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、检查url参数是否包含回调函数字段
         * 2、有字段则添加字段在测试
         * */
        //1.请求的url中含redirect敏感参数
        String querystring = BurpReqRespTools.getQuery(entity.getRequestResponse());
        if (querystring != null) {
            List<String> payloads = new ArrayList<>();
            Map<String, Object> qm = BurpReqRespTools.getQueryMap(entity.getRequestResponse());
            for (String paramname : qm.keySet()) {
                if (CommonStore.REDIRECT_SCOPE.contains(paramname)) {
                    if (isBypass) {
                        payloads.addAll(getBypassPayload(paramname,qm.get(paramname).toString(), querystring));
                    } else {
                        payloads.addAll(getPayload(paramname,qm.get(paramname).toString(), querystring));
                    }
                }
            }
            for (String payload_query : payloads) {
                //新的请求包
                CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getMethod(entity.getRequestResponse()),
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                        payload_query,
                        BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                        BurpReqRespTools.getContentType(entity.getRequestResponse()),
                        new RedirectCallback(this));
            }
        } else {
            CommonStore.callbacks.printError("[Redirect] 不满足前置条件1: 必须要有查询参数\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }

    /**
     * 获取请求的payload
     * @param originValue 参数值
     * @param querystring 完整的
     * @return List<String>
     */
    private List<String> getPayload(String paranname, String originValue, String querystring){
        List<String> ret = new ArrayList<>();
        // 加载payload的模版
        String payload = "http://evil.com/";
        if (!originValue.equals("")) {
            // 将原参数值替换，形成新的querystring
            ret.add(querystring.replace(originValue, payload));
        } else {
            ret.add(querystring.replace(String.format("%s=",paranname), String.format("%s=%s",paranname, payload)));
        }

        return ret;
    }

    /**
     * 获取请求的payload,bypass
     * @param originValue 参数值
     * @param querystring 完整的
     * @return List<String>
     */
    private List<String> getBypassPayload(String paranname, String originValue, String querystring){
        List<String> ret = new ArrayList<>();
        // 获取原参数值中的域名,默认为当前请求的host:port,避免参数值是urlpath，获取不到域名的情况
        String originDomain = BurpReqRespTools.getHttpService(entity.getRequestResponse()).getHost() + ":" + BurpReqRespTools.getHttpService(entity.getRequestResponse()).getPort();
        Pattern domain_patern = Pattern.compile("(http[s]?:)?//(.*?)[/&\"]+?\\w*?");
        Matcher m_domain = domain_patern.matcher(originValue);
        if (m_domain.find()){
            originDomain = m_domain.group(2);
        }
        // 加载payload的模版
        List<String> payloads = SourceLoader.loadSources("/payloads/RedirectPayloadsTemplete.bbm");
        // 用于编码的特殊字符
        String[] encodeStr = new String[]{"@",":","/","://"};
        // 根据模版构造payload
        for (String templete : payloads) {
            if (!templete.startsWith("#") && !templete.equals("")) {
                String payload;
                if (!originValue.equals("")) {
                    // 将原参数值替换，形成新的querystring
                    payload = querystring.replace(originValue, templete.replaceAll("#domain#", originDomain));
                } else {
                    payload = querystring.replace(String.format("%s=", paranname), String.format("%s=%s", paranname, templete.replaceAll("#domain#", originDomain)));
                }
                // 处理#encode#的payload
                if (templete.contains("#encode#")) {
                    for (String s : encodeStr) {
                        // 将原参数值替换，形成新的querystring
                        payload = payload.replaceAll("#encode#", CommonStore.helpers.urlEncode(s));
                    }
                }
                ret.add(payload);
            }
        }
        return ret;
    }
}


class RedirectCallback implements Callback {
    UselessTreeNodeEntity entity;
    LogEntry logEntry;
    TaskImpl task;

    public RedirectCallback(TaskImpl task){
        this.task = task;
        this.entity = ((Redirect)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "Redirect");
        if (((Redirect)task).isBypass) {
            this.logEntry.Comments = "try Bypass!!";
        }
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[RedirectCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = requestResponse;
        logEntry.Status = (short) response.code();
        //检查响应头Location
        if (response.isRedirect()) {
            String location = response.headers().get("Location");
            if (location != null && location.contains("evil.com")) {
                logEntry.hasVuln();
                entity.color = "red";
            } else {
                logEntry.onResponse();
                // 尝试bypass，bypass=false才会进行绕过测试
                if (!((Redirect)task).isBypass) {
                    Redirect bypass = new Redirect(entity);
                    bypass.isBypass = true;
                    bypass.run();
                }
            }
        } else if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("evil.com")) { //检查响应体中，有些是页面加载后重定向
            logEntry.hasVuln();
            entity.color = "red";
            logEntry.Comments += "Redirect and inResp";
        } else {
            // 更新本次验证的结果
            logEntry.onResponse();
            CommonStore.logModel.update();
            // 尝试bypass，bypass=false才会进行绕过测试
            if (!((Redirect)task).isBypass) {
                Redirect bypass = new Redirect(entity);
                bypass.isBypass = true;
                bypass.run();
            }
        }
        CommonStore.logModel.update();
    }
}