LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := trace_demo
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	demo.cpp 

LOCAL_C_INCLUDES := external/traces/include

include $(BUILD_TRACED_EXECUTABLE)
