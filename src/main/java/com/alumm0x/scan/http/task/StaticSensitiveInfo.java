package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticSensitiveInfo extends StaticTaskImpl {

    public static String name = "SensitiveInfo";
    public static String comments = "识别响应中是否包含敏感信息";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticSensitiveInfo(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -响应中的敏感信息
        List<StaticCheckResult> sens = checkSensitiveInfo(entity.getRequestResponse());
        if (sens != null && sens.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(sens);
        }
    }

    /**
     * 检查响应中的敏感信息
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkSensitiveInfo(IHttpRequestResponse requestResponse) {
        byte[] body = BurpReqRespTools.getRespBody(requestResponse);
        // 1.get请求获取数据才可能存在批量泄漏信息的可能，post/put/patch这种是更新数据，一般是单一用户信息
        // 2.有查询参数，这样才有批量的可能
        // 3.有响应才检测
        if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("get")
                && BurpReqRespTools.getQuery(requestResponse) != null
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
}

