LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
APP_ABI := arm64-v8a
LOCAL_CFLAGS += -fPIE -pie
LOCAL_MODULE := memory_dump
LOCAL_SRC_FILES := memory_dump.c
include $(BUILD_EXECUTABLE)
