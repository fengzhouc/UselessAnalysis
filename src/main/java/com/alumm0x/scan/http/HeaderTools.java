package com.alumm0x.scan.http;

import com.alumm0x.util.CommonStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class HeaderTools {

    public HeaderTools(){

    }

    //用于排除csrf的，记录常规的头部名称
    public static boolean inNormal(String headerName){
        return CommonStore.rfc_reqheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //认证的请求头
    public static boolean isAuth(String headerName){
        return CommonStore.auth_header.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //排出标准和可能的自定义认证的请求头
    public static boolean noAuth(String headerName){
        // 是rfc的头部，然后排出rfc的认证头部，这样剩下的就是非认证头部了
        return CommonStore.rfc_reqheader.contains(headerName.toLowerCase(Locale.ROOT)) && 
                !CommonStore.auth_header.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //websocket的请求头
    public static boolean isWebsocket(String headerName){
        return CommonStore.ws_reqheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    //cors的响应头
    public static boolean isCors(String headerName){
        return CommonStore.cors_respheader.contains(headerName.toLowerCase(Locale.ROOT));
    }

    // 设置xff的头部
    public static List<String> setXFF(){
        List<String> xffHeaderName = new ArrayList<>();
        xffHeaderName.add("X-Forwarded-For: 127.0.0.1");
        xffHeaderName.add("X-Originating-IP: 127.0.0.1");
        xffHeaderName.add("X-Remote-IP: 127.0.0.1");
        xffHeaderName.add("X-Remote-Addr: 127.0.0.1");

        return xffHeaderName;
    }
}
