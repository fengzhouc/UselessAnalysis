package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticParamPhoneEmail extends StaticTaskImpl {

    public static String name = "ParamPhoneEmail";
    public static String comments = "识别请求参数中包含手机号或email的场景,可能存在消息轰炸";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticParamPhoneEmail(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 检测请求参数中是否包含手机号或邮箱，可能存在轰炸风险
        List<StaticCheckResult> hong = checkPhoneEmail(entity.getRequestResponse());
        if (hong != null && hong.size() > 0){
            entity.addTag("可能存在短信/邮箱轰炸");
            entity.addMap(hong);
        }
    }

    /**
     * 检查请求参数中是否包含手机号及邮箱，可能是验证码获取的请求
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkPhoneEmail(IHttpRequestResponse requestResponse) {
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        String desc = "";
        String phoneRegex = "['\"&<;\\s/,]+?1(3\\d|4[5-9]|5[0-35-9]|6[567]|7[0-8]|8\\d|9[0-35-9])\\d{8}['\"&<;\\s/,]+?"; //手机号的正则
        String emailRegex = "\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*"; //邮箱的正则
        Pattern patternPhone = Pattern.compile(phoneRegex);
        Pattern patternEmail = Pattern.compile(emailRegex);
        //如果有响应才检测
        if (reqBody.length > 0) {
            String body_str = new String(reqBody);
            //先检测是否存在url地址的参数，正则匹配
            Matcher matcherPhone = patternPhone.matcher(body_str);
            Matcher matcherEmail = patternEmail.matcher(body_str);
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
        }
        if (querys.size() > 0) {
            for (Object value : querys.values()) {
                Matcher matcherPhone = patternPhone.matcher(value.toString());
                Matcher matcherEmail = patternEmail.matcher(value.toString());
                if (matcherPhone.find()) {
                    desc += "queryPhone";
                    desc += "\n" + matcherPhone.group();
                    while (matcherPhone.find()) { //每次调用后会往后移
                        desc += "\n" + matcherPhone.group();
                    }
                    desc += "\n";
                }
                if (matcherEmail.find()) {
                    desc += "queryEmail";
                    desc += "\n" + matcherEmail.group();
                    while (matcherEmail.find()) { //每次调用后会往后移
                        desc += "\n" + matcherEmail.group();
                    }
                    desc += "\n";
                }
            }
        }
        if (!desc.equals("")) {
            List<StaticCheckResult> results = new ArrayList<>();
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "短信/邮件轰炸风险";
            result.risk_param = desc;
            result.fix = "因为提交的数据中含有手机号或邮箱，可能是发送短信或邮件的接口";
            results.add(result);
            return results;
        }
        return null;
    }
}

