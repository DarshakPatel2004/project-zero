import json
from typing import List

METHOD_INVOKE_HOOK = """
Java.perform(function() {
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function(obj, args) {
        var cls = obj !== null ? Java.use(obj.$className) : null;
        var clsName = cls ? obj.$className : 'null';
        var methodName = this.getName();
        if (clsName.indexOf('java.') === 0 || clsName.indexOf('android.') === 0) {
            return this.invoke(obj, args);
        }
        var argStr = [];
        if (args) {
            for (var i = 0; i < args.length && i < 8; i++) {
                try {
                    argStr.push(String(args[i]));
                } catch (e) {
                    argStr.push('<unable to stringify>');
                }
            }
        }
        send(JSON.stringify({
            hook: 'method_invoke',
            ts: Date.now(),
            data: {
                clazz: clsName,
                method: methodName,
                args_preview: argStr
            }
        }));
        return this.invoke(obj, args);
    };
});
"""

URL_OPENCONNECTION_HOOK = """
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.implementation = function() {
        var urlStr = this.toString();
        send(JSON.stringify({
            hook: 'url_openconnection',
            ts: Date.now(),
            data: {
                url: urlStr,
                host: this.getHost(),
                port: this.getPort(),
                protocol: this.getProtocol()
            }
        }));
        return this.openConnection();
    };
});
"""

STRING_INIT_HOOK = """
Java.perform(function() {
    var String = Java.use('java.lang.String');
    var Charset = Java.use('java.nio.charset.Charset');
    String.$init.overload('[B').implementation = function(bytes) {
        var preview = '';
        if (bytes && bytes.length > 0) {
            var len = Math.min(bytes.length, 64);
            var arr = [];
            for (var i = 0; i < len; i++) {
                arr.push(bytes[i]);
            }
            preview = JSON.stringify(arr);
        }
        send(JSON.stringify({
            hook: 'string_init_bytes',
            ts: Date.now(),
            data: {
                byte_length: bytes ? bytes.length : 0,
                byte_preview: preview,
                str_value: this.$init(bytes).toString().substring(0, 256)
            }
        }));
        return this.$init(bytes);
    };
    String.$init.overload('[B', 'java.nio.charset.Charset').implementation = function(bytes, charset) {
        var preview = '';
        if (bytes && bytes.length > 0) {
            var len = Math.min(bytes.length, 64);
            var arr = [];
            for (var i = 0; i < len; i++) {
                arr.push(bytes[i]);
            }
            preview = JSON.stringify(arr);
        }
        var result = this.$init(bytes, charset);
        send(JSON.stringify({
            hook: 'string_init_charset',
            ts: Date.now(),
            data: {
                byte_length: bytes ? bytes.length : 0,
                byte_preview: preview,
                charset: charset ? charset.toString() : 'unknown',
                str_value: result.toString().substring(0, 256)
            }
        }));
        return result;
    };
});
"""

CIPHER_DOFINAL_HOOK = """
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    var callCount = {};
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var threadId = Process.getCurrentThreadId();
        if (!callCount[threadId]) callCount[threadId] = 0;
        callCount[threadId]++;
        if (callCount[threadId] > 50) {
            return this.doFinal(input);
        }
        var result = this.doFinal(input);
        var resultStr = '';
        if (result) {
            try {
                resultStr = String(result).substring(0, 256);
            } catch (e) {}
        }
        var algo = 'unknown';
        try {
            algo = this.getAlgorithm();
        } catch (e) {}
        send(JSON.stringify({
            hook: 'cipher_dofinal',
            ts: Date.now(),
            data: {
                algorithm: algo,
                input_len: input ? input.length : 0,
                output_len: result ? result.length : 0,
                output_preview: resultStr
            }
        }));
        return result;
    };
    Cipher.doFinal.overload('[B', '[I', '[I').implementation = function(input, offset, len) {
        var threadId = Process.getCurrentThreadId();
        if (!callCount[threadId]) callCount[threadId] = 0;
        callCount[threadId]++;
        if (callCount[threadId] > 50) {
            return this.doFinal(input, offset, len);
        }
        var result = this.doFinal(input, offset, len);
        var resultStr = '';
        if (result) {
            try {
                resultStr = String(result).substring(0, 256);
            } catch (e) {}
        }
        var algo = 'unknown';
        try {
            algo = this.getAlgorithm();
        } catch (e) {}
        send(JSON.stringify({
            hook: 'cipher_dofinal',
            ts: Date.now(),
            data: {
                algorithm: algo,
                input_len: input ? input.length : 0,
                output_len: result ? result.length : 0,
                output_preview: resultStr
            }
        }));
        return result;
    };
});
"""

CLASSLOADER_LOADCLASS_HOOK = """
Java.perform(function() {
    var ClassLoader = Java.use('java.lang.ClassLoader');
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(className) {
        send(JSON.stringify({
            hook: 'classloader_loadclass',
            ts: Date.now(),
            data: {
                class_name: className
            }
        }));
        return this.loadClass(className);
    };
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libPath, parent) {
        send(JSON.stringify({
            hook: 'dexclassloader_init',
            ts: Date.now(),
            data: {
                dex_path: dexPath,
                optimized_dir: optimizedDir,
                lib_path: libPath
            }
        }));
        return this.$init(dexPath, optimizedDir, libPath, parent);
    };
});
"""


def get_active_hooks() -> List[str]:
    from analysis.dynamic.config import settings
    hooks = []
    if settings.ENABLE_HOOK_METHOD_INVOKE:
        hooks.append(METHOD_INVOKE_HOOK)
    if settings.ENABLE_HOOK_URL_OPENCONNECTION:
        hooks.append(URL_OPENCONNECTION_HOOK)
    if settings.ENABLE_HOOK_STRING_INIT:
        hooks.append(STRING_INIT_HOOK)
    if settings.ENABLE_HOOK_CIPHER_DOFINAL:
        hooks.append(CIPHER_DOFINAL_HOOK)
    if settings.ENABLE_HOOK_CLASSLOADER:
        hooks.append(CLASSLOADER_LOADCLASS_HOOK)
    return hooks


def build_frida_script() -> str:
    hooks = get_active_hooks()
    return "\n\n".join(hooks)


def hook_count() -> int:
    return len(get_active_hooks())
