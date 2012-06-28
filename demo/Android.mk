LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= libshared-demo-1
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES :=								\
	shared-demo-1.cpp							\

include $(BUILD_TRACED_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE:= libshared-demo-2
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES :=								\
	shared-demo-2.cpp							\

include $(BUILD_TRACED_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := trace_demo
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	demo.cpp 

LOCAL_C_INCLUDES := external/traces/include

LOCAL_CFLAGS = -Xlinker -E
LOCAL_SHARED_LIBRARIES = libshared-demo-1 libshared-demo-2
include $(BUILD_TRACED_EXECUTABLE)
