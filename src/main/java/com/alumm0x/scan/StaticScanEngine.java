package com.alumm0x.scan;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

import org.reflections.Reflections;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

/*
 * 被动检查不会重放请求，仅基于当前请求的内容识别一些场景及风险
 */
public class StaticScanEngine  {

    public static Set<Class<? extends StaticTaskImpl>> tasks;

    // 获取StaticTaskImpl的子类，其就是实现的所有检测项
    static {
        Reflections reflections = new Reflections("com.alumm0x");
        tasks = reflections.getSubTypesOf(StaticTaskImpl.class);
    }

    public static void StaticCheck(UselessTreeNodeEntity entity) {
        // 遍历tasks,对当前请求进行被动检查
        for (Class<? extends StaticTaskImpl> task : tasks) {
            try {
                // 反射获取实例
                Constructor<?> cons = task.getConstructor(UselessTreeNodeEntity.class);
                // 获取待调用的方法
                Method run = task.getMethod("run");
                // 运行方法
                run.invoke(cons.newInstance(entity));
            } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | InstantiationException e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }
    }
}
