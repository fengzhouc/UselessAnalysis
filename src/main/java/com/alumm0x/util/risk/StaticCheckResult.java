package com.alumm0x.util.risk;

/**
 * 检查结果的对象
 */
public class StaticCheckResult {
    // 对应什么问题，也就是问题描述吧，比如ssrf
    public String desc;
    // 问题详情，可能的风险参数
    public String risk_param;
    // 修复建议
    public String fix;

}
