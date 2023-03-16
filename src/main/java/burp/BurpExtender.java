package burp;

import com.alumm0x.listeners.HttpListener;
import com.alumm0x.ui.UIShow;
import com.alumm0x.util.CommonStore;
import java.awt.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, ITab {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 存储核心类
        CommonStore.callbacks = callbacks;
        // 存储数据处理类
        CommonStore.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("UselessAnalysis");

        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(new HttpListener());

        callbacks.addSuiteTab(this);
    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public String getTabCaption() {
        return "UselessAnalysis";
    }

    @Override
    public Component getUiComponent() {
        return UIShow.getUI();
    }
}
