LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
APP_ABI := arm64-v8a
LOCAL_CFLAGS += -fPIE -pie
LOCAL_MODULE := memdump
LOCAL_SRC_FILES := memdump.c
include $(BUILD_EXECUTABLE)
