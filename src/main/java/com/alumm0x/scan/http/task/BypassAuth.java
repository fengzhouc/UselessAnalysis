package com.alumm0x.scan.http.task;

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
import java.util.Arrays;
import java.util.List;

public class BypassAuth extends TaskImpl {

    public static String name = "BypassAuth";
    public static String comments = "绕过鉴权检测。通过url的特殊字符构造请求url，访问成功则存在风险。";
    public static String fix = "一般都是因为url标准化处理有问题，然后又是通过url去匹配做鉴权的。";

    public UselessTreeNodeEntity entity;

    public BypassAuth(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 绕过url鉴权
         */
        //条件：403/401禁止访问的才需要测试
        if (BurpReqRespTools.getStatus(entity.getRequestResponse()) == 401 || BurpReqRespTools.getStatus(entity.getRequestResponse()) == 403){
            List<String> payloads = SourceLoader.loadSources("/payloads/BypassAuth.bbm");

            // 将path拆解
            List<String> bypass_path = createPath(payloads, BurpReqRespTools.getUrlPath(entity.getRequestResponse()));

            for (String bypass : bypass_path) {
                //url有参数
                String url = BurpReqRespTools.getUrl(entity.getRequestResponse()).replace(BurpReqRespTools.getUrlPath(entity.getRequestResponse()), bypass);
                CommonStore.okHttpRequester.send(url,
                        BurpReqRespTools.getMethod(entity.getRequestResponse()),
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                        BurpReqRespTools.getQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                        BurpReqRespTools.getContentType(entity.getRequestResponse()),
                        new BypassAuthCallback(this));

            }
        }else{
            CommonStore.callbacks.printError("[BypassAuth] 不满足前置条件: 必须要是响应状态码是401/403\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }

    private List<String> createPath(List<String> bypass_str, String urlpath){
        // 将path拆解
        String[] paths = urlpath.split("/");
        List<String> bypass_path = new ArrayList<String>();
        // 添加bypass，如:/api/test
        // /api;/test
        // /api/xx;/../test
        for (String str : bypass_str) {
            for (int i = 0; i< paths.length; i++){
                if (!"".equalsIgnoreCase(paths[i])) { //为空则跳过，split分割字符串，分割符头尾会出现空字符
                    String bypassStr = paths[i] + str;
                    StringBuilder sb = new StringBuilder();
                    for (int j = 0; j < paths.length; j++) {
                        if (!"".equalsIgnoreCase(paths[j])) { //为空则跳过，split分割字符串，分割符头尾会出现空字符
                            if (i == j) {
                                sb.append("/").append(bypassStr);
                                continue;
                            }
                            sb.append("/").append(paths[j]);
                        }
                    }
                    bypass_path.add(sb.toString());
                }
            }
        }
        return bypass_path;
    }
}

class BypassAuthCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public BypassAuthCallback(TaskImpl task){
        this.task = task;
        this.entity = ((BypassAuth)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "BypassAuth");
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
        //如果状态码200,然后响应内容不同，则存在url鉴权绕过
        if (response.isSuccessful() && Arrays.equals(BurpReqRespTools.getRespBody(entity.getRequestResponse()), BurpReqRespTools.getRespBody(requestResponse))) {
            logEntry.hasVuln();
        } else {
            logEntry.onResponse();
        }
    }
}
