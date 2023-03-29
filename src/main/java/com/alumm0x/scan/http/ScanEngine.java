package com.alumm0x.scan.http;

import com.alumm0x.scan.http.task.*;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

public class ScanEngine {

    public static void addScan(String poc, UselessTreeNodeEntity entity) {
        switch (poc) {
            case "IDOR":
                new IDOR(entity).run();
                break;
            case "Redirect":
                new Redirect(entity).run();
                break;
            case "Csrf":
                new Csrf(entity).run();
                break;
            case "JsonCsrf":
                new JsonCsrf(entity).run();
                break;
            case "BeanParamInject":
                new BeanParamInject(entity).run();
                break;
            case "BypassAuth":
                new BypassAuth(entity).run();
                break;
            case "WebSocketHijacking":
                new WebSocketHijacking(entity).run();
                break;
            case "Ssrf":
                new Ssrf(entity).run();
                break;
            case "Upload":
                new UploadSecure(entity).run();
                break;
            case "JWT":
                new JWTSensitiveMessage(entity).run();
                new JWTWithOutSign(entity).run();
                new JWTSignNone(entity).run();
                break;
            case "Cors":
                new Cors(entity).run();
                break;
            case "JsonpCors":
                new JsonpCors(entity).run();
                break;
           case "ReflectXss":
                new ReflectXss(entity).run();
                break;
            default:
                CommonStore.callbacks.printError("do not has this tash: " + poc);
        }
    }
}
