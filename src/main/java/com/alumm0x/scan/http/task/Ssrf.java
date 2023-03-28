package com.alumm0x.scan.http.task;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ssrf extends TaskImpl {

    public static String name = "Ssrf";
    public static String comments = "服务端的跨站请求检测。参数中是url的，将构造恶意地址，查看响应是否响应的地址。";
    public static String fix = "对于参数是url的，后端需要白名单限制。";
    public boolean dnslog = false;
    public IBurpCollaboratorClientContext collaboratorClientContext;

    public UselessTreeNodeEntity entity;
    public Ssrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        collaboratorClientContext = CommonStore.callbacks.createBurpCollaboratorClientContext();
        String payload = collaboratorClientContext.generatePayload(true);
        String regex = "http[s]?://(.*?)[/&\"]+?\\w*?"; //分组获取域名
        String evilHost = "evil6666.com";
        //如果有body参数，需要多body参数进行测试
        if (BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0){
            //1.先检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())));
            if (matcher.find()){//没匹配到则不进行后续验证
                String domain = matcher.group(1);
                // 修改为别的域名
                String req_body = dnslog ? new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).replace(domain, payload) : new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).replace(domain, evilHost);
                //新的请求包
                CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getMethod(entity.getRequestResponse()),
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                        BurpReqRespTools.getQuery(entity.getRequestResponse()),
                        req_body.getBytes(StandardCharsets.UTF_8),
                        BurpReqRespTools.getContentType(entity.getRequestResponse()),
                        new SsrfCallback(this));
            }
        }else if (BurpReqRespTools.getQuery(entity.getRequestResponse()) != null){
            //1.先检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(BurpReqRespTools.getQuery(entity.getRequestResponse()));
            if (matcher.find()){//没匹配到则不进行后续验证
                String domain = matcher.group(1);
                CommonStore.callbacks.printOutput(domain);
                // 修改为别的域名
                String req_query = dnslog ? BurpReqRespTools.getQuery(entity.getRequestResponse()).replace(domain, payload) : BurpReqRespTools.getQuery(entity.getRequestResponse()).replace(domain, evilHost);
                //新的请求包
                CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getMethod(entity.getRequestResponse()),
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                        req_query,
                        BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                        BurpReqRespTools.getContentType(entity.getRequestResponse()),
                        new SsrfCallback(this));
            }
        }else{
            CommonStore.callbacks.printError("[Ssrf] 不满足前置条件: 必须要有请求参数\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }
}

class SsrfCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public SsrfCallback(TaskImpl task){
        this.task = task;
        this.entity = ((Ssrf)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "Ssrf");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (((Ssrf)task).dnslog) {
            logEntry.Comments = "try DnsLog";
            try {
                TimeUnit.SECONDS.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            List<IBurpCollaboratorInteraction> ret = ((Ssrf) task).collaboratorClientContext.fetchAllCollaboratorInteractions();
            if (ret.size() > 0){
                logEntry.hasVuln();
                for (IBurpCollaboratorInteraction i :
                        ret) {
                    logEntry.Comments += i;
                }
            } else {
                logEntry.onResponse();
            }
        } else {
            // 检查响应中是否存在flag
            if (new String(BurpReqRespTools.getRespBody(entity.getRequestResponse())).contains("evil6666.com")) {
                logEntry.hasVuln();
                logEntry.Comments = "in Resp.";
                tryDnslog();
            } else if (response.isSuccessful()) {
                logEntry.hasVuln();
                logEntry.Comments = "并没有在响应中呈现，需要在使用dnslog的url确认是否会发起请求";
                tryDnslog();
            } else {
                logEntry.onResponse();
            }
        }
        CommonStore.logModel.update();
    }

    /**
     * 尝试dnslog，验证ssrf
     */
    private void tryDnslog(){
        Ssrf ssrf = new Ssrf(this.entity);
        ssrf.dnslog = true;
        ssrf.run();
    }
}