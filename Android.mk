LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
	LOCAL_MODULE := qmiserial2qmuxd
	LOCAL_SRC_FILES := qmiserial2qmuxd.c

	LOCAL_CFLAGS := -std=c99 -Wall -Wextra -Werror
	LOCAL_LDFLAGS := -llog
include $(BUILD_EXECUTABLE)
