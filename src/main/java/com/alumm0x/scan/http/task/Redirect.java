package com.alumm0x.scan.http.task;

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

public class Redirect extends TaskImpl  {

    public static String name = "Redirect";
    public static String comments = "任意重定向检测。会根据特征匹配可能影响重定向的参数，构造恶意数据，重访请求是否重定向地址与构造的一致。";

    boolean isBypass = false; //标记bypass，callback的时候可以判断
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
        if (querystring.contains("redirect=")
                || querystring.contains("redirect_url=")
                || querystring.contains("redirect_uri=")
                || querystring.contains("callback=")
                || querystring.contains("url=")
                || querystring.contains("goto=")
                || querystring.contains("callbackIframeUrl=")
        ) {
            String nobypass = "redirect=http://evil.com/test&" +
                    "redirect_url=http://evil.com/test&" +
                    "redirect_uri=http://evil.com/test&" +
                    "callback=http://evil.com/test&" +
                    "url=http://evil.com/test&" +
                    "goto=http://evil.com/test&" +
                    "callbackIframeUrl=http://evil.com/test&" +
                    querystring;
            // bypass就删除schema
            String bypass = "redirect=//evil.com/test&" +
                    "redirect_url=//evil.com/test&" +
                    "redirect_uri=//evil.com/test&" +
                    "callback=//evil.com/test&" +
                    "url=//evil.com/test&" +
                    "goto=//evil.com/test&" +
                    "callbackIframeUrl=//evil.com/test&" +
                    querystring;
            String new_query = isBypass ? bypass : nobypass;

            //新的请求包
            CommonStore.okHttpRequester.send(BurpReqRespTools.getUrl(entity.getRequestResponse()),
                    BurpReqRespTools.getMethod(entity.getRequestResponse()),
                    BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                    new_query,
                    BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                    BurpReqRespTools.getContentType(entity.getRequestResponse()),
                    new RedirectCallback(this));
        }else{
            CommonStore.callbacks.printError("[Redirect] 不满足前置条件: 必须要有匹配特征的参数名\n" +
                    "##url: "+ BurpReqRespTools.getUrlWithQuery(entity.getRequestResponse()));
        }
    }
}


class RedirectCallback implements Callback {
    UselessTreeNodeEntity entity;
    LogEntry logEntry;
    TaskImpl task;

    public RedirectCallback(TaskImpl task){
        this.task = task;
        this.entity = ((Redirect)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(),"Redirect");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        logEntry.Comments = "";
        CommonStore.logModel.update();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = requestResponse;
        if (response.isSuccessful()) {
            //检查响应头Location
            if (response.isRedirect()) {
                String location = response.headers().get("Location");
                if (location != null && location.contains("evil.com")) {
                    logEntry.hasVuln();
                    logEntry.Comments = "";
                    logEntry.Status = (short) response.code();
                }
            } else if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("evil.com")) { //检查响应体中，有些是页面加载后重定向
                logEntry.hasVuln();
                logEntry.Comments = "Redirect and inResp";
                logEntry.Status = (short) response.code();
            }else {
                // 不为bypass才会进行绕过测试
                if (!((Redirect)task).isBypass) {
                    Redirect bypass = new Redirect(entity);
                    bypass.isBypass = true;
                    bypass.run();
                }
            }
        } else {
            logEntry.onResponse();
            logEntry.Comments = "";
            logEntry.Status = (short) response.code();
        }
        CommonStore.logModel.update();
    }
}