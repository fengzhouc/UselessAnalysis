package com.alumm0x.scan.http.task.passive;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticStraceError extends StaticTaskImpl {

    public static String name = "StraceError";
    public static String comments = "识别响应中含有异常堆栈信息";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticStraceError(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -响应中的堆栈异常信息
        List<StaticCheckResult> err = checkStraceError(entity.getRequestResponse());
        if (err != null && err.size() > 0){
            entity.addTag("可能存在堆栈异常");
            entity.addMap(err);
        }
    }

    /**
     * 检测是否存在异常上抛到用户侧
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkStraceError(IHttpRequestResponse requestResponse) {
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
}

