LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE=libtrace_parser
LOCAL_MODULE_TAGS := optional
LOCAL_ARM_MODE := arm

LOCAL_SRC_FILES := \
	trace_metadata_util.c \
	halt.c \
	cached_file.c \
	trace_parser.c

LOCAL_C_INCLUDES := external/traces/include
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libtrace_user
LOCAL_MODULE_TAGS := optional
LOCAL_ARM_MODE := arm
LOCAL_C_INCLUDES := external/traces/include

LOCAL_SRC_FILES := \
	trace_metadata_util.c \
	halt.c \
	shm_files.c \
	trace_user.c

include $(BUILD_STATIC_LIBRARY)