LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE=simple_trace_reader
LOCAL_MODULE_TAGS := optional
LOCAL_ARM_MODE := arm

LOCAL_SRC_FILES := \
	simple_trace_reader.c \

LOCAL_C_INCLUDES := external/traces/include
LOCAL_STATIC_LIBRARIES=libtrace_parser
include $(BUILD_EXECUTABLE)
