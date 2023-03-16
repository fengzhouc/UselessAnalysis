package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.HeaderTools;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class JsonCsrf extends TaskImpl {
    public static String name = "JsonCsrf";
    public static String comments = "json格式的跨站请求伪造检测。将请求的content-type改成form表单的形式提交，若能够处理且返回正常则存在风险。";
    public static String fix = "后端服务的api限制content-type，请求数据是json的则限制为application/json。";

    public UselessTreeNodeEntity entity;

    public JsonCsrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、jsonCsrf：修改content-type为form表单的
         *   （1）检查响应头中是否包含Access-Control-Allow-Credentials且为true
         *   （2）再检查Access-Control-Allow-Origin是否为*
         *   （3）不满足（2）则修改/添加请求头Origin为http://evil.com，查看响应头Access-Control-Allow-Origin的值是否是http://evil.com
         * */
        //csrf会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (check(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Cookie") != null){
            /*
             * 1、请求头包含application/json
             */
            String ct = check(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Content-Type");
            if (ct != null && ct.contains("application/json")) {
                List<String> new_headers = new ArrayList<String>();
                String CT = "Content-Type: application/x-www-form-urlencoded";
                //新请求修改content-type
                boolean hasCT = false;
                for (String header :
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse())) {
                    // 剔除掉csrf头部
                    if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                        if (header.toLowerCase(Locale.ROOT).contains("content-type")) {
                            header = header.replace("application/json", "application/x-www-form-urlencoded");
                            hasCT = true;
                        }
                        new_headers.add(header);
                    }
                }
                //如果请求头中没有CT，则添加一个
                if (!hasCT) {
                    new_headers.add(CT);
                }
                if (!BurpReqRespTools.getMethod(entity.getRequestResponse()).equalsIgnoreCase("get")) {
                    //新的请求包:content-type
                    CommonStore.okHttpRequester.send(BurpReqRespTools.getUrl(entity.getRequestResponse()),
                            BurpReqRespTools.getMethod(entity.getRequestResponse()),
                            new_headers,
                            BurpReqRespTools.getQuery(entity.getRequestResponse()),
                            BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                            "application/x-www-form-urlencoded",
                            new JsonCsrfCallback(this));

                }
            }else{
                CommonStore.callbacks.printError("[JsonCsrf] 不满足前置条件2: ContentType必须要是'application/json'\n" +
                        "##url: "+ BurpReqRespTools.getUrlWithQuery(entity.getRequestResponse()));
            }
        }else{
            CommonStore.callbacks.printError("[JsonCsrf] 不满足前置条件1: 必须要有'Cookie'\n" +
                    "##url: "+ BurpReqRespTools.getUrlWithQuery(entity.getRequestResponse()));
        }
    }
}

class JsonCsrfCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public JsonCsrfCallback(TaskImpl task){
        this.task = task;
        this.entity = ((Csrf)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "JsonCsrf");
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
        if (response.isSuccessful()){
            //如果状态码相同及响应内容一样，则可能存在问题
            if (BurpReqRespTools.getStatus(entity.getRequestResponse()) == BurpReqRespTools.getStatus(requestResponse)
                    && Arrays.equals(BurpReqRespTools.getRespBody(entity.getRequestResponse()), BurpReqRespTools.getRespBody(requestResponse))) {
                logEntry.hasVuln();
                logEntry.Comments = "";
                logEntry.Status = (short) response.code();
            } else {
                logEntry.onResponse();
                logEntry.Status = (short) response.code();
                logEntry.Comments = "";
            }
        } else {
            logEntry.onResponse();
            logEntry.Comments = "";
            logEntry.Status = (short) response.code();
        }
        CommonStore.logModel.update();
    }
}
