LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := trace_dumper
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	trace_user_stubs.c \
	filesystem.c \
	trace_dumper.c

LOCAL_C_INCLUDES := external/traces/include
LOCAL_STATIC_LIBRARIES=libtrace_parser
include $(BUILD_EXECUTABLE)
