
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libtransport-tls
LOCAL_CATEGORY_PATH := libs
LOCAL_DESCRIPTION := TLS Transport library
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -DTTLS_API_EXPORTS -fvisibility=hidden -std=gnu99
LOCAL_SRC_FILES := \
	src/ttls.c \
	src/ttls_async.c \
	src/ttls_bio.c \
	src/ttls_socket.c \
	src/ttls_utils.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libulog

include $(BUILD_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE := ttls-server
LOCAL_CATEGORY_PATH := multimedia
LOCAL_DESCRIPTION := TLS Transport library server test program
LOCAL_CFLAGS := -std=gnu99
LOCAL_SRC_FILES := \
	tests/ttls_server.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libtransport-tls \
	libulog

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE := ttls-client
LOCAL_CATEGORY_PATH := multimedia
LOCAL_DESCRIPTION := TLS Transport library client test program
LOCAL_CFLAGS := -std=gnu99
LOCAL_SRC_FILES := \
	tests/ttls_client.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libtransport-tls \
	libulog

include $(BUILD_EXECUTABLE)
