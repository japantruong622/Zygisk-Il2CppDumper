//
// Created by Perfare on 2020/7/4.
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>

void hack_start(const char *game_data_dir) {
    bool load = false;
    for (int i = 0; i < 10; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        } else {
            sleep(1);
        }
    }
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    //TODO 等待houdini初始化
    sleep(5);

    // API 35+: dlopen("libart.so") bi chan boi linker namespace -> dung xdl
    void *vm_symbol = nullptr;
    auto libart = dlopen("libart.so", RTLD_NOW);
    if (libart) {
        vm_symbol = dlsym(libart, "JNI_GetCreatedJavaVMs");
    }
    if (!vm_symbol) {
        LOGI("dlsym failed, fallback to xdl for libart");
        auto xart = xdl_open("libart.so", XDL_TRY_FORCE_LOAD);
        if (xart) {
            vm_symbol = xdl_dsym(xart, "JNI_GetCreatedJavaVMs", nullptr);
            if (!vm_symbol) vm_symbol = xdl_sym(xart, "JNI_GetCreatedJavaVMs", nullptr);
        }
    }
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) vm_symbol;
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    if (!JNI_GetCreatedJavaVMs) {
        LOGE("JNI_GetCreatedJavaVMs not found");
        return false;
    }
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    // API 35+: dlopen("libhoudini.so"/libnb.so) bi chan namespace -> dung xdl
    void *nb_handle = dlopen("libhoudini.so", RTLD_NOW);
    bool nb_via_xdl = false;
    std::string nb_name = "libhoudini.so";
    if (!nb_handle) {
        nb_name = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", nb_name.c_str());
        nb_handle = dlopen(nb_name.c_str(), RTLD_NOW);
    }
    if (!nb_handle) {
        LOGI("dlopen nb failed, fallback to xdl");
        nb_handle = xdl_open("libhoudini.so", XDL_TRY_FORCE_LOAD);
        if (!nb_handle) nb_handle = xdl_open(nb_name.c_str(), XDL_TRY_FORCE_LOAD);
        nb_via_xdl = (nb_handle != nullptr);
    }
    if (nb_handle) {
        LOGI("nb %p (via_xdl=%d)", nb_handle, nb_via_xdl);
        void *itf = nullptr;
        if (nb_via_xdl) {
            itf = xdl_sym(nb_handle, "NativeBridgeItf", nullptr);
            if (!itf) itf = xdl_dsym(nb_handle, "NativeBridgeItf", nullptr);
        } else {
            itf = dlsym(nb_handle, "NativeBridgeItf");
        }
        LOGI("NativeBridgeItf %p", itf);
        auto callbacks = (NativeBridgeCallbacks *) itf;
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;

    // Load frida-gadget arm64 (da duoc x86 side copy vao app cache).
    if (game_data_dir) {
        std::string gp = std::string(game_data_dir) + "/cache/gadget.so";
        void *gh = dlopen(gp.c_str(), RTLD_NOW);
        LOGI("gadget dlopen(%s) = %p", gp.c_str(), gh);
        if (!gh) {
            // Fallback: load qua NativeBridge (nhu NativeBridgeLoad cua module).
            void *nb = dlopen("libhoudini.so", RTLD_NOW);
            void *itf = nullptr;
            if (nb) itf = dlsym(nb, "NativeBridgeItf");
            if (!itf) {
                auto xnb = xdl_open("libhoudini.so", XDL_TRY_FORCE_LOAD);
                if (xnb) {
                    itf = xdl_sym(xnb, "NativeBridgeItf", nullptr);
                    if (!itf) itf = xdl_dsym(xnb, "NativeBridgeItf", nullptr);
                }
            }
            struct NBCallbacks {
                uint32_t version; void *initialize; void *(*loadLibrary)(const char *, int);
                void *(*getTrampoline)(void *, const char *, const char *, uint32_t);
                void *isSupported; void *getAppEnv; void *isCompatibleWith; void *getSignalHandler;
                void *unloadLibrary; void *getError; void *isPathSupported; void *initAnonymousNamespace;
                void *createNamespace; void *linkNamespaces; void *(*loadLibraryExt)(const char *, int, void *);
            };
            auto cb = (NBCallbacks *) itf;
            if (cb && cb->loadLibraryExt) {
                gh = cb->loadLibraryExt(gp.c_str(), RTLD_NOW, (void *) 3);
                LOGI("gadget via bridge = %p", gh);
            }
            if (gh && cb && cb->getTrampoline) {
                auto ginit = (jint (*)(JavaVM *, void *)) cb->getTrampoline(gh, "JNI_OnLoad", nullptr, 0);
                if (ginit) {
                    jint gr = ginit(vm, nullptr);
                    LOGI("gadget JNI_OnLoad = %d", gr);
                }
            }
        } else {
            auto ginit = (jint (*)(JavaVM *, void *)) dlsym(gh, "JNI_OnLoad");
            if (ginit) {
                jint gr = ginit(vm, nullptr);
                LOGI("gadget JNI_OnLoad = %d", gr);
            }
        }
    }

    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}

#endif